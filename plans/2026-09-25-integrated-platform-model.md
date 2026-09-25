# One integrated Andrix platform model

Status: consolidated design proposal following the
[deliberate decision audit](2026-09-25-deliberate-decision-audit.md). The owner requested sustained
collaborative design and challenge before implementation resumes. Accepted requirements remain
in the [architecture](../docs/architecture.md). This proposal does not select production permission
defaults, signer topology, key policy, UID ranges, resource constants or a package language. It
adds no runtime qualification. The terminal logging defect remains unfixed and the native
reservation store and factory remain inactive or unimplemented as described in current work.

## 1. The recommendation

Build **one Android system with explicit ownership boundaries**, not a universal privileged
Andrix daemon and not two systems disagreeing about identities or installed software.

The proposed structure is:

```text
Human intent and ordinary tools
  |                            |
  | ordinary computation       | deliberate system change
  v                            v
Native account controller      Installation authorization and trust policy
  | binds real authorities       | scoped grants, not ordinary account membership
  |                              +--> signing authority
  |                              +--> deployment authority
  |                              +--> elevation authority
  v
Trusted factory / init supervision <--- declared maintenance and disruption
  |
Protected principal manager
  +--> ordinary work scopes and descendants
  +--> scoped Android API bindings
  +--> managed environment leases
  ^
Terminal, editor and SSH clients through explicit delegation

Android UserManager, CE/storage, PMS, permission/AppOps, ActivityManager,
network/power, package/APEX/update/boot services remain authoritative.
Kernel objects enforce the actual process, descriptor and resource boundaries.
```

These are logical responsibilities. Some may share a process; others need separate protected
roles. The exact number of daemons or SELinux domains is not itself the architecture. Separation
must reduce real authority and failure coupling without creating needless IPC and duplicated state.

### Concrete directions to take forward

1. A **dedicated native account policy subject backed by Package Manager**, rather than assigning
   the ordinary login to arbitrary third party APK code. A minimal platform managed package is
   the first representation to test; a framework native subject remains the alternative if the
   package model needs incoherent exceptions.
2. A **native runtime participant in Android's real UID policy**, with one captured containment
   owner. A helper is not a substitute for the fact that native work exists.
3. **Durable native identity and UID reservation**, separate from ordinary package settings
   recovery and from volatile manager/work instances.
4. **Epoch bound authority and exact supervision**, preserving revocation while investigating
   how to remove unnecessary dependence on short observation reply deadlines.
5. **Explicit managed retention**, protected ordinary publication and real reader ownership,
   alongside ordinary owner files. The later [cost review](2026-09-25-native-package-retention.md)
   recommends current selections for interactive work, conservative automatic retention and
   explicitly pinned environments, rather than pinning every shell by default.
6. **Per class component transactions** that know their identity, data, reader, API and disruption
   consequences. Signing, native commit and actual retirement remain separate facts.

These recommendations choose a coherent direction to test. They do not claim every proposed
interface already exists or that all implementation alternatives are equally good.

## 2. What is already established, and what is not

Existing evidence supports important parts of this structure:

- Captured work containment, exact Stop, late creation cleanup, ordinary execution and descendant
  lifetime have finite host and Android results on the earlier reserved UID vehicle.
- Genuine CE observation, old epoch refusal and new explicit work after withdrawal/regrant have
  finite results. They do not prove physical key erasure or all pressure/suspend behavior.
- Ordinary Android recognized UIDs used notification and mock location services with real
  ownership and grant controls. The diagnostic launch/bootstrap was not the supported entry.
- PMS reservation and exact Selection components passed host checks and an actual framework
  module build. The production factory, native policy integration and new store are not enabled.
- Focused SystemUI builds, staged changes, checkpoint rejection controls and forward good code
  restoration worked within one declared platform cohort.
- Protected signing of one ordinary APK and independent portable identity recovery have bounded
  results. A complete multi-format protected transaction and physical key assurance remain open.

The missing proof is the **composition of these contracts**. Neither a test count nor a collection
of individually reasonable modules demonstrates the complete owner experience.

## 3. State ownership

| State or decision | Owner | What it must not become |
| --- | --- | --- |
| Android user existence, type and serial | UserManager | An Andrix copy of the user database |
| CE preparation, key provenance and current availability | Android storage/credential authorities, with explicit native observation/provider interfaces | A test of lockscreen state, path readability or fscrypt version alone |
| Package/policy identity, app ID allocation, grants and actual installed state | PMS and the existing permission/policy services | A planner's fictional installed database or a caller selected UID |
| Native designation and its durable incarnation | Native account controller, referencing Android users and PMS | Authority inferred from APK installation, signer, home inode or a mutable label |
| Scoped client delegation | Native account controller; grants bind to an incarnation and separately scoped private records where appropriate | A global permission bit standing in for target, effect, lifetime and recreation binding |
| UID reservation occupancy | PMS native reservation store | An execution grant or another UID allocator |
| Environment process lifetime and enclosing retirement | init/kernel and the captured supervisor interface | Andrix work policy in PID 1 or cleanup by reused PID/path |
| Work identity, admission, Stop and job policy | Protected manager | A terminal's process lifetime or automatic replay after failure |
| Android UID importance and capability state | ActivityManager and its native policy consumers | A shadow TOP flag or a helper's accidental presence |
| Managed API effect | The real Android service; the adapter owns the exact request/lifetime reference | An invented result or a package-wide cleanup guess |
| Installation grants and role trust policy | Installation authorization authority | A native login flag, APK signature alone or the signer's ability to authorize itself |
| Key custody and approved signing operations | Signing authority and actual backend | A universal installation or root grant |
| Desired component selection | Owner intent and authorized managed selection | A declaration that the selected bytes must already be running |
| Deployment attempt and pending native references | Deployment coordinator | A replacement for PMS, apexd or update/boot state |
| Managed objects, profiles, lease records and collection | Store/publication authority, with scope bound holders | World readable private builds, leases lost with a manager, or GC based on a process scan |
| Presentation and input | Clients plus actual Android window/keyguard authority | Work retention, administrator status or fake foreground use |
| Optional history/output and protected security diagnostics | Explicit recording policy | Mandatory transcripts or authority reconstructed from logs |

A canonical native identity record can store designation, reservation and retirement references
in one transaction without copying Android user attributes or permission grants. Keep it small.
Declare field ownership and one serialized persistence interface: PMS controls reservation
mutation; the account controller supplies validated designation changes through that interface.
Two authorities must not independently rewrite the same file.
Full private file delegations and hot API journals need not be serialized into the critical DE
UID record. Their owners may keep separately scoped records referenced by it. The minimum facts
needed to prevent reuse or finish user/account retirement must remain available through the
withdrawal/removal they govern, without copying private contents into DE. Unavailable metadata
means a retained obligation, not guessed retirement. Essential recovery metadata and optional
activity recording are different responsibilities.

## 4. Accounts and their policy subjects

### Recommended primary login

Provision the normal Unix login as part of trusted setup or full Android user creation under the
selected Andrix system. It need not be an arbitrary APK chooser or an extra administrator prompt
just to use ordinary computation.

The first policy carrier to compare is a minimal platform managed account package, potentially
one shared package installed for each full Android user, with a global app ID and distinct UIDs
per user. It contains no arbitrary terminal, editor or third
party application code. A dedicated account signing role does not imply the platform certificate,
a privileged app or additional Android grants.

**Package presence is necessary, not designation.** Ordinary install, `install-existing`, restore,
a manifest declaration or a signer match must not create a Unix login. A durable role binding is
created by the trusted account operation. The installed but undesignated carrier is inert for
native entry. Normal runtime and special permissions remain under Android's actual authorities;
the requested permission surface and defaults are not silently selected here.

A shared package can have one global app ID and distinct user UIDs, grants and CE homes. Its code
is not independently versioned per user. Optional restricted principals can use separately
managed subjects and enforceable credentials/MAC/resource profiles. Denying every Android API
is one possible restricted profile, not the definition of all restricted execution.

### Why this is the first candidate

It reuses package/UID permission, attribution and API machinery exercised through ordinary app
UIDs in the notification and location references, without making an editor's code co-owner of the
login's policy subject. The dedicated carrier itself has not been qualified. Its costs are concrete: account
creation, package lifecycle routing, update continuity and permission UI need integration.

A framework native policy subject is the strongest alternative. It could avoid unsuitable APK
lifecycle assumptions, but would need genuine support in services that currently expect packages.
It should replace the carrier route if that route spreads ad hoc exceptions, imposes an artificial
capability ceiling, forces component lifetime on Unix programs or has worse measured upstream carry.
The number of changed files alone does not decide the comparison.

### Durable native identity

Keep a designation/incarnation distinct from the Android user serial and package name. Removing
and recreating a native account within one Android user must not inherit old grants or effects.
An inode is reusable metadata, not that incarnation.

At minimum distinguish:
- designated and eligible to acquire live authority;
- suspended with data and identity retained;
- retiring with durable obligations and no new admission;
- retired, with any remaining reservation or data obligations explicitly represented.

Enabling or resuming an account never clears its keystore by default. Idempotent deletion is not
a substitute for a retirement protocol. Generic package clear/uninstall/restore paths must not
queue destructive work behind the account transaction's back.

Retaining a home or keys under the old UID retains the UID dependency. Archive or suspend does
not permit reuse merely because no process remains. Release requires approved deletion or verified
migration/export that removes the dependency, plus confirmed retirement of all producers and effects.
RETIRING closes new maintenance, delegation, lease and publication admission. Operations already
submitted under earlier maintenance capabilities retain their tickets and must be reconciled before
retirement completes. Recreated accounts do not automatically inherit old stores or grants; an
explicit verified migration is a different authorized operation.

## 5. Identity and lifetime bindings

Different authorities legitimately mint different identities. One global epoch would obscure
rather than solve their lifetimes.

| Reference | Meaning and issuer | Required binding/invalidation |
| --- | --- | --- |
| User ID and serial | UserManager's user incarnation | Removal/reuse cannot preserve old native authority |
| Native designation/incarnation | Trusted account operation | Durable prior binding; new incarnation on true removal/recreation |
| PMS reservation | Exact app ID hold and identity binding | Held through retirement; restored positive identity requires stored prior package, signer and user binding. Current image verification is not proof of old ownership |
| Binding/policy revision | Current approved package, signer and policy relationship | Revalidate the changed facts, not automatically every unrelated lifetime |
| Framework authority instance | This system_server authority | Its loss ends native work under the settled contract |
| User/CE authority epoch | Actual lifecycle/key authority | Revocation cannot be repaired by a late positive or a new epoch |
| Supervisor instance | init's captured service/scope instance | No replacement until the original's actual retirement |
| Live execution profile | Trusted specialization of one manager | UID/groups/MAC/resources cannot be changed by an ordinary work request |
| Manager/work instance | Manager incarnation and accepted work | Exact retry/Stop; no replay or adoption under a replacement |
| Presentation/delegation | Authorized client and scope | Window state, client identity, grant lifetime and target incarnation matter |
| Helper/API generation | Actual runtime/service instance | No automatic resubscription after loss; retain or retire exact effects |
| Environment generation/lease | Managed dependency closure and its holder | Retain until the relevant future execution/read authority ends |
| Deployment attempt | Protected coordinator's durable operation | Keep native tickets through uncertain outcomes; no resubmission as new work |

Persisted grants need explicit incarnation binding. Live work epochs do not by themselves revoke
old persistent delegations. Conversely, persistent identity does not keep a dead manager live.

## 6. Live authority, factory and Android policy

### Authority and containment

A native account controller in system_server binds current designation, PMS subject, user/CE,
profile and supervisor state. It does not execute owner payloads, allocate independent UIDs or
make a second permission decision over an Android denial.

A trusted factory requests an instance of a declared supervisor template. The template fixes
trusted bootstraps and allowed authority/resource classes; resolved credentials come only from
the authenticated platform controller. Init's existing credential transition is a reuse candidate:
it already clears an empty supplementary group vector and applies an explicit empty capability
set. The manager still verifies all resulting credentials after exec.

Authenticate system_server through actual transport credentials, SID and captured process/channel
authority. It is a zygote child, not an init service named `system_server`. A property, a PID label,
or opening a pidfd on a later reconstructed PID cannot be the whole identity argument.

The manager runs at the principal's ordinary UID in a protected MAC role. Ordinary descendants
run in the worker role, with no root credential change per program and no caller selected trusted
bootstrap. Payload environment and arguments are applied only after the complete transition;
management descriptors are closed before ordinary execution.

### Revocation and entry

The candidate replacement for polling-only liveness has two distinct jobs:

1. An epoch bound admission protocol with a real linearization point against Work Stop and each
   authority revocation. A mutable gate protected against resizing may help trusted participants
   coordinate. It is not an immutable profile and does not create authority by itself. The actual
   revoker, such as the CE tracker or designation controller, must invalidate its registered gate
   before its withdrawal transition when that ordering is claimed. Relaying through the manager
   orders only the manager's observation. Specify mapping ownership and memory ordering; the
   gate coordinates trusted participants, not a new boundary against a compromised manager.
2. A supervisor lifetime/revocation channel that makes init act on the captured scope even when
   the manager is stalled or dead. An epoch descriptor hang up is a candidate signal.

Polling a descriptor and then claiming entry has a race. Multiple descriptors do not make one
atomic lease. The exact protocol must prove which side won entry versus revocation, own every
late created scope and state the framework death window honestly. Closing admission and actual
termination are different facts. Key withdrawal never waits for cleanup.

Keep the existing fail closed protection until the replacement has real race/fault qualification.
The objective is to avoid killing jobs merely because an observation reply is late, not to permit
indefinitely stale authority or pretend cached keys become inaccessible immediately.

### UID state and presentation

Recommend a first class native runtime contribution to Android's UID policy rather than a helper
process standing in for ongoing work. This is a new framework interface proposal, not an existing
qualified API or a result inherited from the reference programs. ActivityManager computes importance/capabilities from real
facts. The kernel/init hierarchy remains the single native containment owner. Platform kill,
freeze and resource actions reach it through exact supervised interfaces, not an unrelated uid/pid
cgroup path.

Native work existence is a running/resource fact. It is not user interaction, foreground authority
or automatic exemption from standby, Doze or network policy. Real window associations supply
presentation contributions. Work submission, file delegation and presentation permission remain
separate. Shared UID foreground effects are a consequence of shared login authority and must not
be advertised as per-program permission isolation.

Managed helpers are still useful for authentic SDK bootstrap and particular APIs. Helper loss can
degrade those APIs or presentation, but must not erase the native participant while work exists.
Helper binding can be compared for presentation propagation; it is not the only source of UID
existence. No universal foreground service, Keep grant or wake lock is required merely to compute.

### Home and resources

Prefer comparing a dedicated CE account home provider against package CE data. The former may
reduce coupling to generic clear/uninstall/restore paths; the latter may reuse package accounting.
Neither is selected solely from a pathname or PMS inode. The provider must establish genuine
user/key/storage provenance through the Android storage authority and supply a verified captured
home. Owner changes to ordinary home mode/group are not reasons to lock the login out.

Use device, principal and work budgets with control headroom and a declared phone backstop.
Per work OOM grouping and a work subtree ceiling below the instance aggregate are candidates for
containing one job's failure. `memory.min`/`memory.low` do not create guaranteed physical capacity.
Pids controllers, quotas, scheduler/LMKD classes and actual shared UID thread costs need measurement.
Do not remove existing guards before a working replacement or turn old limits into product defaults.

## 7. Effects and retirement

A supported API binding must state what it owns and what Stop means.

| Effect class | Examples and rule |
| --- | --- |
| Live scope owned resource | Session/listener/stream which must end with the work under a real service contract |
| Completed persistent effect | Saved output or an acknowledged action which Stop cannot undo |
| Explicit account/service owned effect | An authorized transfer to a longer lived owner, with its own retained obligations |
| Unknown outcome | Submission or retirement not established; do not call it complete or replay it |

A native death token can cover a volatile session within the matching service epoch. Effects
which survive their volatile owner need exact retained operation/effect references and, where
necessary, durable tickets before the mutation. There is no package-wide sweep of effects a new
manager guesses are unowned. There is no claim to log every unmanaged file write or network packet.

Client close, token release or a scheduled callback is not automatically service retirement.
Use the service's actual contract and completion observation. Process admission alone also does
not authorize every later protected effect. Publication, maintenance and other authority crossings
need their own current admission and explicit commit ordering against revocation. Already accepted
writes or native operations can finish late; retain and reconcile them rather than claiming that
process Stop cancelled their effects. Where an API cannot support the
stronger lifetime guarantee, declare that limitation or a different explicit owner; do not relabel
an unknown operation as completed persistent state.

Account retirement first makes RETIRING and its obligations durable, closing new admission across
restarts. It then confirms producer closure and completion of generic asynchronous erasers already
queued before performing approved destructive steps under exact receipts. Init retirement, API
retirement, delegation revocation, home disposition, per-UID key state and package/user changes
have distinct completion evidence. Include restricted subjects and their reservations, managed
store leases/objects and pending publication records in those obligations. Background native cleanup and generic package tasks cannot
later erase a newly created account. Keep the reservation until all dependencies permit release.

## 8. Managed native software without making every update a reboot

Keep three different things:

- ordinary mutable owner files and directly executed builds;
- a small authenticated system base;
- managed native objects and environment generations, private or explicitly shared.

### Protected publication, ordinary authority

Publishing a private package should not require device administration. A publisher under the
principal UID in a protected role is a candidate: it captures supplied content, owns staging,
verifies the object, establishes content integrity and atomically publishes a namespace the
payload cannot mutate. It stays outside the Work Stop lane and follows real CE authority.
It is a fixed trusted publication service, not a caller selectable privileged profile in the
ordinary work request. A publisher process admitted earlier must still pass publication admission;
sharing the work epoch mechanism does not make every filesystem commit atomic with CE withdrawal.
Each publication retains an exact ticket, including unknown outcomes and staging ownership, for
reconciliation under valid authority. Collection cannot discard that staging as unowned.
The private store follows the home provider's CE provenance and lifecycle contract; generic
package clear, uninstall or restore cannot destroy objects while their leases remain live.

Read only mode bits in a payload-writable directory are not trusted immutability. Captured
objects, namespace protection and possibly fs-verity must cover replacement as well as contents.
Unmanaged owner files remain ordinary Unix files; the managed guarantee does not forbid them.

Shared publication is a separate authorized information release and installation effect.
Everything is private by default. A builder's label saying "public" cannot authorize publishing
another user's data. Minimal protected DE holder/object references may retain public shared
objects while private users are locked, without copying commands, contents or private projects
into DE. Privacy and access checks are part of the design, not inferred from a digest.

### Current selections, exact environments and real retention

The [retention refinement](2026-09-25-native-package-retention.md) now recommends two explicit
modes. Ordinary interactive work follows current selections for new commands, with a conservative
store owned retention window covering the selections it could have used. Pinned builds/services
hold exact environment generations and do not hold back every future current selection. This is
a revised proposal, not an implemented or accepted production default. Both modes establish their
retention before entry, keep unknown obligations across failure and coordinate with collection.

For the pinned mode, an explicit managed environment generation is leased at work admission. The store
authority issues and records the lease before the entry gate can be claimed, bound to exact work/environment scope
identity. The manager holds a reference, but the authoritative lease record must outlive or be
recoverable independently of that manager. An issuer restart cannot interpret missing volatile
state as permission to collect. Only exact retirement or definite no-creation facts release the
hold. Its command and library paths identify immutable generation views, not a mutable `current` pointer. Unmodified
fork/exec and later supported library lookup therefore have a stable managed closure. Verify the
actual linker behavior; exact package references remain an alternative to a scoped generation
library view. Do not globally widen Android namespaces.

A pinned long lived shell can explicitly adopt a new generation through a scoped operation which adds
its lease before changing the shell environment. Existing children keep their old environment.
If an engineering bound prevents another lease, refuse/defer adoption or start a fresh scope.
**Never discard an old live lease with a warning to make room.** The owner can see what retains
space and explicitly end obsolete work.

Collection first closes new lease acquisition for a retiring object/generation, then deletes only
when every relevant root and lease is gone. Current selections, explicit pins, recovery material,
pending operations and live scopes retain their closures. Manager failure releases nothing until
captured enclosing retirement is confirmed. Future scheduled execution has its own durable root.
A `/proc` scan is diagnostic, not proof that no later exec or dlopen will need an object.

Pinned mode trades automatic updates inside old shells for explicit consistent environments.
Current mode keeps conventional command selection and uses conservative retention, not a claim
that every path lookup sees one generation. It can retain churn until the oldest current mode
scope retires. Transfers into another scope need the corresponding reference or bound; arbitrary
path strings are not leases. Direct mutable files stay available. Neither mode silently inherits
the other's guarantees. Measure holdback before adding per-command dispatch or new filesystem
machinery solely to obtain finer collection.

## 9. System changes use the runtime model, not a competing one

Ordinary planners/builders resolve owner intent and produce artifacts without installation keys
or root. Logical installation authorization, signing, deployment/publication and elevation are
separate responsibilities. Actual process boundaries should enforce the useful privilege split;
they are not a defense against compromise of the whole kernel.

Installation authorization belongs to device trust policy, not automatic native account membership.
It references real principals and credential bindings and reacts to user removal and revocation.
Signing holds key custody and enforces that policy; it does not appoint its own authority.
General elevation constructs an administrative context before executing an arbitrary owner
command. A presentation window can govern new admissions without owning already accepted work.
The grant's revocation contract must distinguish closing new admission from revoking ongoing use.

### Recommended first hypotheses, not production selections

| Join | First candidate to falsify | Strongest alternative and deciding evidence |
| --- | --- | --- |
| Installation trust realization | Owner controlled signing identities for the roles Andrix builds, preserving third party identities; distribution provenance verified independently | Scoped delegated trust; compare actual native checks, identity data, carry cost, key availability, update time/storage/energy and recovery. Key counts do not force an answer. |
| Whole signing transaction | Protected issuer derives only the approved operation challenges after one fresh authentication, retaining per-operation backend checks | A timed backend window only after explicit threat comparison and owner decision if needed. Existing LockSettings methods are not already the transaction protocol. |
| Coupled platform selection | A signed compatibility/selection manifest for a coherent platform cohort, with guarded overrides between realizations | Explicit native selection or coordinated version projection. Compare real factory/data version, split, rollback, data and external updater cases. |
| Native package selection | Protected objects plus leased managed environments and scoped library resolution | Exact package closures or other evaluated store implementations. Measure cost and UX, not resemblance to a named package manager. |
| Independent repair | Retained signed known good material where usable, plus an independently recoverable signing/installation path when forward repair is necessary | Per-class native rollback, checkpoints and slot fallback are mechanisms to qualify, not interchangeable guarantees. |

Owner signing changes identity data and requires review of embedded trust references, seinfo,
permissions, WebView/provider expectations, update keys and hardware evidence. It is not a claim
that every trust relationship stays unchanged. Routine on-device signing remains a goal; explicit
host signing/recovery is not forbidden, and that host then belongs to the operation's trusted base.

A usable recovery kit can combine clear instructions and trusted identity information without
storing a decryption secret beside its ciphertext or trusting a commitment only from the bundle
being checked. Intact portable material can be copied or rewrapped. A nonexportable device-only
copy cannot magically regenerate a lost portable key. Corruption recovery and compromise rotation
remain different operations.

### Component activation contracts

Each component contract and resolved plan names:

- actual old native base, intended selection and exact artifact closure, including native identity
  store/account format lineage and migration compatibility for every supported rollback target;
- affected package/policy identities, users, credentials and API/helper generations;
- ABI and data compatibility, including later dynamic loads and shared APK code;
- live readers and the mechanism retaining or retiring them;
- signing, installation and disruption authority;
- the native commit boundary, unknown outcome query and retirement observations;
- health criteria, retained recovery roots and any forward repair requirement.

A compatibility cohort is not the lifetime of every native tool or ordinary app. Private framework
interfaces may need exact binding; maintained public APIs may permit independent updates.

An override cannot remain eligible merely because its version integer wins, nor can a cohort
mismatch silently discard an owner choice. A target selection must establish what was carried or
explicitly abandoned and which data transition is safe. Ineligible artifacts remain retained for
reconciliation and recovery. Choosing the factory copy is not safe solely because the override is
ineligible. Supported plans resolve that before activation; unexpected divergence is not guessed
away. A constant `factory + 1` rule is a candidate to test, not the product's version meaning.

### Update and disruption matrix

| Change | Required interpretation |
| --- | --- |
| Ordinary owner file/build | Normal Unix mutation/exec, not platform installation |
| Managed native generation | Current mode new commands follow the current selection while old exact objects remain under its retention contract. Pinned environments change only through a new scope or explicit adoption. No live hold is evicted |
| Ordinary editor/terminal APK | Android code effects can span all users with that package. Lost client presentation or submission does not cancel already accepted independent work |
| Account policy carrier metadata | Maintain under native account maintenance capabilities and the appropriate installation authority. A shared carrier update reaches every affected user/incarnation. Include each in the plan; conflict with a retiring account defers/refuses the global change, not a fictitious per-user exclusion. Keep designation and UID stable; evaluate semantic deltas |
| Permission change | Real Android permission/API policy governs. If that policy decides to kill the UID, the decision must reach native scopes by exact Stop, not only known Java app processes. Not every change is assumed to require a kill |
| Added GID or changed executable profile | Pending until a newly specialized manager. Current unprivileged forks cannot gain groups merely because a database changed. Initial design uses declared restart, not an assumed concurrent handover |
| Removed GID/MAC authority | Enforce revocation of all affected live profiles. No unbounded wait for another consent after the permission has already been withdrawn |
| API/helper update | Keep compatible old generation objects or retire affected sessions under their contract. Not automatically every Unix job, and not automatically no disruption |
| Manager replacement | Old ordinary work ends under the current contract; exact enclosing retirement precedes replacement |
| Framework replacement | Declared framework authority loss ends native work; no replay under a new epoch |
| Persistent component/APEX/image | Use its actual activation class, possible restart/reboot and data/checkpoint limits. Not one universal atomic pointer switch |
| Root change outside management | Deliberate divergence; later managed plans revalidate the actual base rather than silently overwriting it |

Signing completion, native commit, activation/health, data transition and work/API retirement
are separate facts.
A reboot ending processes does not prove a persistent API or data obligation retired. Revocation
closes new effects but cannot erase accepted signatures or committed native operations. Their
original tickets remain owned and are reconciled.

Publication versus cancellation/revocation needs an explicit protected linearization point. If
revocation wins admission, incomplete outputs stay private and no new publication is authorized.
If the publication operation was already accepted, report and reconcile its real outcome, including
a lost acknowledgement or late visible commit. Do not infer ordering from when the UI received a
reply, and do not hold a shared Stop/control lock over filesystem or installer I/O.

## 10. End-to-end event checks

| Event | Required whole-system behavior |
| --- | --- |
| Full user setup | Trusted native designation and real PMS subject/hold, not APK self appointment; home preparation follows genuine CE authority |
| Unlock | Fresh live authority may start a new instance after any old instance retires; configured services create new work only under explicit policy |
| Screen relock | Ordinary jobs persist; presentation/input and new SSH follow locked-access policy; no false CE withdrawal |
| User switch | Does not itself mean Stop or CE loss. Actual Android user/CE/resource events still govern |
| Detach / terminal close | Detach removes presentation; explicit close performs real hangup, not blanket descendant Stop |
| Client dies / reply lost | Accepted work survives; unaccepted attempts and unresolved effects retain their original ownership and identity |
| Genuine authority withdrawal | Close entry under the authority protocol, signal exact supervisor Stop, retire real resources without delaying key withdrawal |
| Observation delayed | No stale positive grants new authority. Reduce false work loss only through a proved independent revocation/liveness design |
| Manager or framework dies | Captured scope cleanup, visible pending/blocked retirement, no old job adoption; API/store ownership reconciles independently |
| Helper dies | Managed API or presentation degrades according to its contract; native UID participation still reflects real work |
| Resource saturation | Declared job/aggregate backstops, surviving control path where promised, visible cause and no phantom cleanup |
| Account suspended with data | Preserve incarnation, UID dependency, home and keys; no automatic clear on resume |
| Account removed/recreated | Durable retirement, closed producers and exact obligations before reuse; a new incarnation cannot inherit stale delegations |
| Native record damaged | Retain known allocation holds; isolate the affected account and repair from trustworthy copies without guessing a signer |
| Native environment/tool update | Respect leases and supported lookup semantics; no removal of a live dependency to make GC succeed |
| Platform update while jobs run | Plan names and obtains authority for actual disruption, carries owner selection or reports conflict, preserves recovery roots |
| Credential reset or admin holder removal | Respond to actual user/CE and derived grant/key events. Do not assume it has no work consequences or pretend accepted native effects vanished |
| Broken UI or signer frontend | Repair uses an independent route, which may restore known good artifacts or produce authorized forward repair from independently recovered signing authority |

## 11. Why this is coherent rather than a list of fixes

The same ownership rule applies at every crossing: **capture the exact object and scope, establish
current authority, accept once, retain uncertain obligations, and release only on the appropriate
retirement fact.** It does not imply one transport, one identifier or one database for everything.

The model separates conflicts which previously looked unavoidable:

- Presentation can disappear without owning ordinary work lifetime.
- An ID can remain occupied while the account's positive authority is unavailable.
- One fresh human signing approval can govern multiple precisely scoped cryptographic operations.
- A new tool selection need not delete dependencies still needed by old work.
- Owner component development need not mean a full source rebuild or disabled verification.
- Recovery need not depend on the UI or signer frontend that just broke.

Some costs remain: shared login authority, explicit environment refresh, resource termination,
reboot class updates, protected backup handling, platform carry and closed firmware. State these
rather than hiding them behind “no compromises”. Improvements must reduce avoidable coupling,
not quietly lower the owner's programmability or security goals.

## 12. Decisive vertical journeys

Implement and qualify joined journeys, rather than accumulating disconnected probes:

1. **Account to ordinary computation:** provision the role, specialize the manager, compile/run an
   unmodified program and descendants, use an actual Android capability, then lose the client UI
   without ending work. Attempt cross-principal access with matching positives.
2. **Authority under stress:** real permission/credential changes, CE withdrawal, delayed observation,
   blocked I/O, CPU/memory/pids pressure, helper and manager/framework death. Verify exact Stop,
   retirement and no stale revival. Test a second Android user and user ID reuse separately.
3. **Managed native generations:** current mode and pinned shell/late exec/dlopen, new profile
   publication, explicit pinned adoption, refused adoption at capacity, conservative holdback,
   cross-scope references, collection racing launch, manager death and locked users holding shared
   dependencies. No observation scan stands in for retention authority.
4. **One complete owner component transaction:** immutable build/import, one approved multi-format
   signing transaction, native installation, declared activation, actual health and independent
   repair. Distinguish lost replies and partial outputs from completed outcomes.
5. **A real upstream transition:** carry a local variant, expose a conflict/missing fix, exercise
   private-cohort and public-interface components, preserve fallback roots and make data effects
   visible. Compare personalization/delegation and component/cached-image realization costs.
6. **Retire and recover identity:** damaged record/copy, PMS settings recovery, valid own-slot
   restoration, wrong signer, suspended data, pending API/keystore operations and interrupted
   removal. No premature UID reuse, package sweep or automatic data clearing.
7. **Recover installation authority:** a credential/holder change, valid and invalid portable
   recovery, then repair a broken frontend through an independent authorized path. A compromise
   rotation drill and physical assurance remain separate gates.

Measure resource and phone impact where the mechanism is actually used. Emulator function does
not establish physical battery, radios, emergency use, hardware signing or firmware recovery.

## 13. What can be settled now and what must remain explicit

The ownership map, binding distinctions, effect classes, retention obligations and per-class
update contracts are recommended as the shared target. They align the accepted goals and existing
evidence and can guide a bounded implementation after review.

First implementation hypotheses are the dedicated PMS policy carrier, an independent CE home
provider comparison, a native UID contribution, epoch admission plus captured supervision,
PMS reservation slots, protected ordinary publication and leased environments. They have clear
falsifiers rather than becoming permanent merely because one fixture works.

Before production, the owner still needs meaningful choices about installation authority holders,
trust realization, stronger compromised-OS signing assurance, permission/delegation defaults and
ordinary disruption policy. Define who may designate, suspend or retire an account and authorize
its destructive data disposition, including cross-user administration. Ordinary account ownership,
Android user administration and device installation authority are not interchangeable. Numeric budgets, path spelling, transport encoding and routine build
steps are engineering work to measure, not a new questionnaire. General root, shared login
semantics, genuine CE authority, portable recovery and whole transaction signing approval are
not reopened as accidental choices.

Implementation remains paused for review of this consolidated proposal. No current timer, key
policy, quota, UID allocation range, package lifecycle guard or cleanup fence is weakened by it.
