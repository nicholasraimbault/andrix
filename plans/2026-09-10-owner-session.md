# First bounded owner session

## Scope

The owner authorized continuing the terminal/workspace slice while leaving Vanadium
unchanged. Reuse pinned GrapheneOS `2026081300`, current frozen base producer
`a28d170`, Android/Bionic, Binder, init, SELinux and credential-encrypted storage.
This is an Andrix-owned prototype, not a browser fork or a Pixel deployment.

First delivery: **unlock → console → create a file → run a native command → detach
→ return**. A full terminal emulator, editor/compiler packaging, multi-user support,
SSH and production update/signing remain later work. Existing core/P5 tests remain
regressions; ordinary APKs do not acquire owner execution authority.

## Implementation boundaries under qualification

- Reserve an unused system_ext AID for the primary user's native owner identity;
  do not use root, shell, system, an ordinary app's identity or a shared UID with
  the UI. The initial scope is Android user 0 only.
- A small init-managed `andrixd` is the coordinator. A distinct owner execution
  SELinux domain runs its child shell under the same bounded Unix owner UID, using
  the existing app-workload policy class rather than changing trusted-daemon
  neverallows. Before owner code, a worker-only inherited syscall restriction
  rejects Binder ioctls/io_uring and sets no_new_privs; the reserved Unix UID must
  not become ambient Android service authority. This is not an APK identity or a
  relaxation of ordinary-app policy. The coordinator's executable, control state
  and Binder interface remain outside
  writable owner code. No capability-based privilege escalation or root shell.
- Create the dedicated home beneath `/data/misc_ce/0` only through Android's real
  CE-preparation event. `UserDataPreparer` sets `sys.user.0.ce_available` after
  preparation; this property is not itself a current keyguard/unlock oracle.
  Validate directory identity, encryption policy and key availability rather than
  fall back to DE storage or create an unencrypted substitute.
- A small Android console uses an explicit signer/package-scoped SELinux identity
  to reach the native Binder service. No platform signer or Android shared UID is
  needed for the console. Reuse only the existing local lab certificate for this
  prototype; production signing is not selected.
- Binder caller UID/user and kernel-supplied SELinux SID are checked, not client-
  supplied identity strings. Unrelated APKs, including a same-signer different
  package, must not gain the service's control identity.
- The console checks Android user-unlocked, keyguard and foreground/focus state.
  It is part of this small trusted UI/control boundary, not an untrusted lifecycle
  oracle. A short renewable attachment lease and detach/death handling fail closed
  if the controller disappears. The first console uses ordinary Android views,
  not WebView, and is line-oriented rather than claiming full VT compatibility.
- Do not hand out the actual PTY master. The daemon keeps it and mediates a bounded
  stream endpoint, so detaching/locking can revoke UI input while the shell and
  bounded output buffer remain. A stale descriptor must not survive reattachment
  as a usable control channel. Relock is not claimed to evict Android CE keys.
- Keep the init-created process cgroup. Establish and read back an aggregate memory
  limit before admitting a session; inherited hard process/FD limits, background
  scheduling and LMKD/OOM integration complement it. Missing bounds fail closed.
  Do not globally turn on a resource mode merely to bypass an admission failure.
  Native children must not be able to escape/raise their inherited limits or
  alter the coordinator's resource/control state.
- Reboot ends processes. Init must reap the entire owned cgroup if the coordinator
  dies, including children that changed Unix process group. User-stop/CE-key-loss,
  screen relock and detachment are distinct lifecycle cases; unsupported cases
  must not be quietly presented as qualified multi-user behavior.

These are prototype implementation choices to test against the exact platform,
not claims of a working owner runtime. Any discovered incompatibility must be
resolved narrowly or recorded as a blocker, without weakening ordinary-app policy.

## Source observations

- `system/core/libcutils/include/private/android_filesystem_config.h` reserves
  7500–7999 for system_ext. `TARGET_FS_CONFIG_GEN` and `oemaids_headers` generate
  the existing Android identity records; no libc/framework UID-table patch.
- `frameworks/base/services/core/java/com/android/server/pm/UserDataPreparer.java`
  prepares CE and signals primary-user availability; `system/vold/FsCrypt.cpp`
  prepares `/data/misc_ce/<user>` with the actual CE policy.
- `system/core/init/service.cpp` creates the service cgroup and registers a supplied
  OOM score with LMKD. Its optional memory-control mode depends on
  `UsePerAppMemcg`; that global flag is absent from the measured base. Merely
  declaring a limit is not evidence it took effect.
- `system/core/libprocessgroup` supports system_ext task profiles and cgroup v2,
  but exact action/UID/path semantics must be respected. Memory-limit readback
  and immutable cgroup ownership are required, not a host mock alone.
- Android supplies user/keyguard state APIs. The listener permission is conditional
  on a platform flag; do not assume an arbitrary privileged APK automatically
  receives it. A foreground console with explicit state checks and a short lease
  avoids inventing a new unlock service or broad signature grants.

The first builds retained new-layer failures: a generated shared AIDL library
would have landed in the generic system partition (changed to static linkage),
an undefined local policy macro, and policy assertions rejecting daemon-class
execution of writable home code and unallowlisted socket ioctls. The owner worker
now uses Android's existing app-workload policy class, with local Binder syscall
restriction instead of attempting to subtract upstream generic grants. Socket
ioctls use the existing narrow Unix-socket allowlist. No upstream policy assertion,
framework code or Vanadium component is disabled or patched to pass these checks.
These changes still require fresh compilation/runtime qualification.

## Checks

1. Host tests of real native core/state logic: initial closed state, lease expiry,
   detach/replacement, bounded buffers, invalid dimensions/requests, unavailable
   CE/bounds, descriptor lifetime and child setup/reaping failures.
2. Build native service/runner/console and compile the exact SELinux/product inputs.
   Inspect generated identities, permissions, signer mapping and packaged artifacts.
   No old platform patch series or Vanadium substitution.
3. Frozen-image emulator proof through normal UI: actual first unlock, native UID/
   domain/capability and resource observations, persistent home, shell/PTY, detach/
   return and relock rejection. Observe CE separately from keyguard. No forged
   setup state, screenshot-protection bypass, root-adbd or operator grants.
4. Negative APK access, ordinary P5 private-exec denial, authenticated read-only
   `/usr`, Android `/etc`, SELinux and reboot checks. Record failures and cleanup.

## Evidence

New private evidence is selected by `out/owner-session/EVIDENCE`; the earlier
7,217-file connected-preparation seal is immutable. Initial I13 review was
cancelled without substantive findings; primary source inspection supplies this
plan. The first source-review pipeline hit SIGPIPE through `head`; the failed
observation and corrected bounded reads are retained. No guest has started for
this milestone at plan creation.
