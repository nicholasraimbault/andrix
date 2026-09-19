# Owner-session prototype

Andrix-owned system_ext components on GrapheneOS's maintained base, with the
opt-in private-policy bridge below. Vanadium, phone services, platform signer and
ordinary-app execution policy are not replaced.
See the [milestone](../plans/2026-09-10-owner-session.md) for scope and qualification.

**Development opt-in:** `ANDRIX_OWNER_SESSION=true` with the existing
`andrix_gos_cf_arm64_only_phone-cur-userdebug` product. The baseline without that
flag does not install the owner service/console or include their UID/policy inputs.
Apply and check the [single private-policy bridge](../patches/grapheneos-2026081300/README.md)
before an opt-in build. It defines only the new native owner/home boundary, guarded
off for other products; no public policy API or existing-domain permission change.
This is not a production interface or a qualified phone installation.

Factory APKs and update APK pairs are different packaging inputs. The console's
factory build does **not** install a v4 sidecar: the APK is authenticated by the
read-only system image, not per-file fs-verity. Installing a sidecar there caused
Package Manager to reject the factory app; that failed window is retained.

Prepare a separate APK Signature Scheme v4 update pair with
`scripts/proof/terminal_update.py`. In the emulator, supply both the verified APK
and its matching `.idsig` through a normal install session using its scoped ADB
connection:

```sh
adb install-multiple -r AndrixTerminal.apk AndrixTerminal.apk.idsig
```

GrapheneOS requires fs-verity for system-package updates; a streamed APK alone was
correctly rejected. Never disable that check to install a development build. Verify the **v4 result**, not only
`apksigner`'s overall exit status, which can succeed through another valid scheme.

## Internal work admission candidate

The [next admission slice](../plans/2026-09-18-work-admission-gate.md) introduces an
original epoch binding and a shared atomic execution gate. The real platform observer
supplies its existing instance/generation and query issue based deadline. Stop closes
that gate without the admission or UI mutex; queued wake data cannot reopen it.

At `d211b25`, 404 host tests, focused optimized/sanitizer and separate process controls,
normal/Keep Android native builds and the frozen Soong host admission test passed.
Those component checks were followed by the [finite Android owner launch trial](../plans/2026-09-19-owner-launch-qualification.md)
at `fbccb19`: 412 host tests, matching selected images and actual owner programs, profiles,
ordinary app negatives, queued Stop, independent work and manager cleanup controls.
The [new admission CE trial](../plans/2026-09-19-owner-admission-ce-trial.md) at `8621e11`
then passed its finite real withdrawal, old request refusal, normal PIN regrant, fresh
owner execution and final cleanup controls, after 420 host tests and matching selected
artifacts. Earlier incomplete attempts remain recorded. The held helper's own startup
timeout won before regrant; no live late helper or physical key erasure claim follows.
The public work API and broader qualification remain unfinished.
Existing Console/plain/Keep paths do not call these new admission methods, and their
behavior below remains unchanged. Gate closure is not process or resource cleanup.

The [bounded registry core](../plans/2026-09-19-work-registry-core.md) now adds internal
reservation capacity, identities that are not reused, ordered request streams, immutable
Start matching, exact retained controls and creator/observation/cleanup bookkeeping.
Focused host and sanitizer checks exercise its actual gate objects and selected thread
races. Process and resource facts in those checks are supplied by the test adapter, not
Android or kernel measurements. No new control service, caller authentication, descriptor
import or persistent recorder is installed. The public crossing and real backend still
need integration and qualification.

## Components

- `andrixd`: non-root UID/GID `system_ext_andrix` (7500), dedicated coordinator
  domain. Registers `andrix.owner.session` only after real identity and resource
  admission checks. Init owns the aggregate memory limit and complete cgroup cleanup.
- `andrix-session-runner`: fixed image-owned entry into the separate native owner
  domain, same Unix UID. This is not `appdomain` or an installed APK: the explicit
  private-policy bridge permits native owner execution of only its own home data,
  without changing existing trusted-daemon or ordinary-APK permissions. Checks inherited
  bounds/home and installs an additional worker-only seccomp filter before exec:
  `no_new_privs`, no Binder ioctl family or io_uring. This prevents the reserved
  UID from becoming an ambient Android service client despite upstream generic
  Binder grants. The coordinator/Android are not filtered. Establishes the PTY and
  execs Android's shell.
- `AndrixTerminal` (`dev.andrix.terminal`): small privileged system_ext platform-API
  console, signed with the existing local Andrix lab certificate, **not the platform
  key**. No shared UID or APK-declared Android permissions. A signer-and-package
  mapping supplies only this app's control domain; GrapheneOS's implicit PM metadata
  remains separate from APK declarations. ServiceManager bootstrap uses the explicit
  system-app non-SDK API flag, not a global hidden-API exemption.

The console is a trusted UI gate. It checks primary-user unlock, keyguard,
interactive display and foreground focus; the daemon authenticates Binder UID/SID.
The console also registers its own process-local Binder lifetime; in plain mode,
that process's death ends native work even if the Activity had detached. A 1.5-second
CLOCK_BOOTTIME lease closes stale UI attachments. The actual PTY master
never leaves the daemon: the UI gets a separately labelled stream that can be shut
down/replaced, and ordinary APKs cannot use that stream even if handed its FD.
This is a bounded UI-policy mechanism, not cryptographic attestation of keyguard.
A received connection has guarded pending ownership while Main prepares its parser;
the ordinary heartbeat renews pending or active ownership. Pending input stays
blocked until identity-checked promotion. Cancellation/expiry retires ownership
before local FD shutdown, and late replies cannot restore it. The lease duration
is unchanged; this is not a shell-readiness barrier or automatic retry.

The home is `/data/misc_ce/0/andrix`, prepared only following Android's real CE
preparation event. The daemon never creates a missing/fallback home. Mode/owner,
no-symlink traversal and fscrypt-v2 policy are checked, alongside the trusted
console's actual Android UserManager unlock state. Native code does **not** query
vold-only key-status ioctls or claim an independent key-status measurement. The normal
owner may edit/execute their own home content under the owner domain; the UI and
coordinator cannot execute it. Relock does not mean CE-key eviction. User-stop/key
removal must be tested separately; no multi-user support is claimed.

## Bounds and lifecycle

- Init-created cgroup v2 retained; fixed 256 MiB aggregate memory, swap disabled,
  group OOM killing. The daemon can request application of these fixed bounds
  only within UID7500's cgroup path. Init applies them; readback must succeed.
  No global per-app-memcg toggle or cgroup-control ownership is given to owner code.
- Inherited hard limits: 32 owner tasks, 128 FDs per process, no core dumps and
  64 MiB per file. The file limit is **not a total storage quota**. Background
  scheduling, nice floor10 and OOM adjustment700 keep work below phone-critical
  services; actual behavior and native-device suitability still need qualification.
- One shell/session in this prototype; the 128 KiB output journal retains bytes
  until parser acknowledgement and exposes gaps after overflow. Input/UI queues
  are bounded as well. This is not an unlimited or durable transcript.
- Detach/lease expiry revokes UI input and keeps the shell/limited output tail.
  Explicit End, shell exit, controller/coordinator death or a reported Android
  `UserManager.isUserUnlocked() == false` state ends the session (not screen relock): Android
  init kills/reaps the entire service cgroup, not only a Unix process group which
  children could escape with `setsid`. End is a termination request, not storage
  durability acknowledgement. Plain-mode processes do not outlive the Console
  APK process; Android may reclaim it while cached. Explicit kept work has the
  separate lifetime described below. Reboot ends processes,
  not the intended home data. The scoped lifecycle trials below are not general
  service, user stop or complete key removal qualification.
- No automatic shell start on daemon boot, arbitrary privileged exec API, caller-
  supplied path/UID/environment, descriptor-based access to the real PTY, root
  shell, adopted identity or ordinary APK hardening override.

## Verification status

Portable native core and host guard-negative tests exercise actual C++ logic, not
Android mocks pretending to supply CE storage. The actual production stream-pump
methods also run against real host PTYs/sockets with an explicit FD/clock adapter;
stale streams close while the PTY survives. Worker-filter tests exercise real
host syscall denial, retained PTY ioctls and fork/exec inheritance, not Android
SELinux or ABI qualification. Source-contract tests check opt-in scope, signer
mapping and init bounds. Build, compiled policy, image contents and Android runtime
results remain separate evidence.

Bounded Android emulator checks cover native shell/PTY access, editing, C/C++ builds,
Make, same-owner debugging, return/relock, ordinary-app negatives and complete End.
The [milestones](../plans/current.md) retain product outcomes and limitations; detailed
runs are private evidence. No capabilities or general cross-domain tracing were added
for debugging. Broad IME/language, assistive-service, pressure and phone compatibility
are not implied by these checks.

The [two fixed lifecycle trials](../plans/2026-09-14-lab-lifecycle-faults.md) exercised
actual CE locking with a vold busy file outcome and one delayed genuine snapshot reply.
Old work groups were removed and fresh work recovered without reboot. Complete key
removal is not claimed. Resource exhaustion, broader descriptor/race, user stop,
service and native phone qualification remain open. These checks do not qualify
networking privacy, production updates or power loss durability.

## Presentation and terminal behavior

The [separation review](../plans/2026-09-16-work-terminal-separation.md) distinguishes
native terminal process role from workload retention. `TerminalProcessState` routes
real owned child exits and bounds client retirement. It grants no continuation or
Android authority.

The next API candidate adds typed work metadata and exact work Stop independently of
terminal attachment. Console can discover observed work while foreground and unlocked,
then End that selected Binder/work identity without attaching or repairing a parser.
An old response cannot replace a newer work selection. Stop acceptance remains a request,
not completed cleanup. Metadata grants no terminal or retention authority. Existing
creation modes, lifetime policies, runner commands and full init cleanup remain in
place; explicit work creation and new policies are subsequent work.


The [terminal adapter](../plans/2026-09-10-owner-tools.md) connects pinned
VT libraries to the native stream through an Andrix-owned, process-free session
adapter. Output carries session/offset frames and is retained until acknowledged
after parsing. In plain mode, Activity recreation keeps the parser/checkpoint within
the same Console process; process death ends native jobs. A detected plain-mode gap
blocks input and requires End/new work, rather than inventing a screen.

The separately opt-in [New kept mode](keep/README.md) uses a notification-backed
platform grant and tmux from creation. Console loss or detach retires its client/PTY,
not server/panes. Return uses a fresh client, presentation ID and parser/journal;
it never rebases the old parser over discarded output. End and notification Stop
terminate the complete native work. It does not convert an already-running plain
shell and remains subject to the recorded failure/release limits.

The parser cannot access Android clipboard through escape sequences; explicit user
selection actions use a separate callback.
Keys shows/hides the normal IME; holding it opens Android's input-method picker.
Accessibility descriptions use the actual visible rows, capped at 8,192 UTF-16 code
units with an explicit truncation marker, and require the bound foreground/unlocked
UI. Events carry no cached terminal text. These are viewport descriptions, not a
complete transcript or an alternative file-access API.

The bounded Android VT/`vi` and touch-input windows are recorded in the milestone.
They do not turn host checks into full View/IME, accessibility or terminal
compatibility qualification.
