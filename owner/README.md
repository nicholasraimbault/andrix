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
The console also registers its own process-local Binder lifetime; that process's
death ends the native session even if the Activity had detached. A 1.5-second
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
  durability acknowledgement. This first prototype's processes do not outlive the
  console APK process; Android may reclaim it while cached. Reboot ends processes,
  not the intended home data. Independent long-lived service/user-stop/key-eviction
  qualification remains future work, not a claimed feature here.
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

Frozen producer `e02bd6a` has now demonstrated the bounded first delivery in the
ARM64 Cuttlefish emulator: normal PIN unlock, native UID7500 shell/PTY, CE home
file creation and private-code execution, ordinary-app negatives, detach/return,
relock revocation, whole-group cleanup and file persistence across reboot/cold
restart. The full host suite passed 274 tests. Failure/timeout windows are retained;
see the [milestone](../plans/2026-09-10-owner-session.md) for precise results.

The subsequent `9e5f816` candidate demonstrated a native VT view and `vi` edit/save/
script execution, including return to an unsaved editor buffer, relock, explicit
output-gap recovery and persistence through reboot. Its input trial used Android
keyboard events and visible touch controls. A version-3 console update then restored
automatic focus, demonstrated real on-screen-keyboard editing and exposed bounded
foreground viewport text through Android accessibility. The touch test explicitly
requested software input alongside Cuttlefish's physical keyboard and restored that
preference afterward. The later [compiler image](../plans/2026-09-11-native-compiler.md)
demonstrated native C compilation/run and C++ with a project-private runtime,
including after reboot. The [subsequent C++ defaults](../plans/2026-09-11-cxx-defaults.md)
now let ordinary standalone C++ compile/run without a runtime copy, with a separate
working shared-runtime profile. The [project/input follow-up](../plans/2026-09-11-owner-project-input.md)
also demonstrates multi-file builds, edited-header rebuilds, failed-build recovery and
reboot persistence. Its cold first-Attach failure led to the
[pending-lease correction](../plans/2026-09-11-cold-attachment.md), which passed first
Attach after both tested boots while preserving input gating, expiry and revocation.
The earlier failures remain recorded. The [native Make follow-up](../plans/2026-09-11-native-build-tools.md)
then demonstrated incremental dependency tracking, no-op builds, failed-build recovery,
recursive jobs and rebuilding after reboot, using the same bounded owner identity.
The [native debugger trial](../plans/2026-09-12-native-debugger.md) added owner-labelled
PTYs and same-owner tracing, with actual C/C++ breakpoint/step/variable/return checks
and coordinator/app negatives. No capabilities or general cross-domain tracing were
added. Broad IME/language and assistive-service compatibility are not claimed.

Resource-exhaustion tests, all adversarial descriptor/race cases on Android,
user-stop/key eviction, long-lived services and native phone qualification remain
open. Neither offline execution nor these lifecycle checks qualify networking
privacy, production updates or power-loss durability.

The [terminal/tools follow-up](../plans/2026-09-10-owner-tools.md) now connects pinned
VT libraries to the native stream through an Andrix-owned, process-free session
adapter. Output carries session/offset frames and is retained until acknowledged
after parsing. Activity recreation keeps the parser/checkpoint within the same
console process; process death still ends native jobs. A detected output gap blocks
input and requires an explicit End/new session, rather than silently inventing a
screen or injecting a redraw command. The parser cannot access Android clipboard
through escape sequences; explicit user selection actions use a separate callback.
Keys shows/hides the normal IME; holding it opens Android's input-method picker.
Accessibility descriptions use the actual visible rows, capped at 8,192 UTF-16 code
units with an explicit truncation marker, and require the bound foreground/unlocked
UI. Events carry no cached terminal text. These are viewport descriptions, not a
complete transcript or an alternative file-access API.

The bounded Android VT/`vi` and touch-input windows are recorded in the milestone.
They do not turn host checks into full View/IME, accessibility or terminal
compatibility qualification.
