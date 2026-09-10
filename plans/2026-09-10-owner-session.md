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
  SELinux domain runs its child shell under the same bounded Unix owner UID,
  outside `appdomain`. A digest-guarded, opt-in private policy bridge permits only
  this new native tier to execute its own home data, denies its cgroup writes and
  restricts its exec transition to the coordinator. Existing domains retain their
  restrictions. Before owner code, a worker-only inherited syscall restriction
  rejects Binder ioctls/io_uring and sets no_new_privs; the reserved Unix UID must
  not become ambient Android service authority. This is not an APK identity or a
  relaxation of ordinary-app policy. The coordinator's executable, control state
  and Binder interface remain outside writable owner code. No capability-based privilege escalation or root shell.
- Create the dedicated home beneath `/data/misc_ce/0` only through Android's real
  CE-preparation event. `UserDataPreparer` sets `sys.user.0.ce_available` after
  preparation; this property is not itself a current keyguard/unlock oracle.
  Validate directory identity and encryption policy together with Android's
  authenticated user-unlocked state; never fall back to DE storage or create an
  unencrypted substitute. Native code does not claim an independent key-status
  measurement or use vold-only key-status/management ioctls.
- A small Android console uses an explicit signer/package-scoped SELinux identity
  to reach the native Binder service. No platform signer or Android shared UID is
  needed for the console. Reuse only the existing local lab certificate for this
  prototype; production signing is not selected.
- Binder caller UID/user and kernel-supplied SELinux SID are checked, not client-
  supplied identity strings. Unrelated APKs, including a same-signer different
  package, must not gain the service's control identity.
- The console checks Android user-unlocked, keyguard and foreground/focus state.
  It is part of this small trusted UI/control boundary, not an untrusted lifecycle
  oracle. It registers a process-local Binder lifetime. Controller process death
  ends the native session; a short renewable attachment lease separately revokes
  UI access on detachment/relock. This prototype does not keep jobs alive after
  Android reclaims the console process. The first console uses ordinary Android views,
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
execution of writable home code and unallowlisted socket ioctls. An app-workload
attempt exposed Android's launcher assertion and inherited zygote/run-as dynamic
transitions. Rather than borrow that identity model, the
[one-file private-policy bridge](../patches/grapheneos-2026081300/README.md) now defines
the distinct **native owner tier**: only its own home data may be executable,
only its coordinator may enter it through exec, and owner cgroup writes are denied.
The local worker syscall filter prevents ambient Binder authority; socket ioctls
use the existing narrow allowlist. No existing process is exempted or granted new
permissions. This revises the initial system_ext-only/app-workload assumptions;
it is not a defect in GrapheneOS. No framework/browser code or global policy check
is disabled. Vold retains exclusive key-management/status authority: the prototype
uses read-only encryption-policy metadata, Android user state and controller death,
not an invented native unlock oracle. Fresh compilation and runtime qualification
remain necessary.

## Checks

1. Host tests of real native core/state logic: initial closed state, lease expiry,
   detach/replacement, bounded buffers, invalid dimensions/requests, unavailable
   CE/bounds, descriptor lifetime and child setup/reaping failures.
2. Build native service/runner/console and compile the exact SELinux/product inputs.
   Inspect generated identities, permissions, signer mapping and packaged artifacts.
   Record the one conditional private-policy bridge separately from the unchanged
   manifest HEAD; no old platform patch series or Vanadium substitution.
3. Frozen-image emulator proof through normal UI: actual first unlock, native UID/
   domain/capability and resource observations, persistent home, shell/PTY, detach/
   return and relock rejection. Observe CE separately from keyguard. No forged
   setup state, screenshot-protection bypass, root-adbd or operator grants.
4. Negative APK access, ordinary P5 private-exec denial, authenticated read-only
   `/usr`, Android `/etc`, SELinux and reboot checks. Record failures and cleanup.

## Module-stage checkpoint

The seventh module/policy build exited 0 in **194.608 seconds** after the retained
failures above and a correction to the new assertion's handling of Android's
existing debug overlay domain. Native coordinator/runner, console, optional
negative APK, policy compilation, neverallow and compatibility checks completed.
The D8/R8 API37 warning and existing compatibility-tool warnings remain in the log;
SDK/security checks were not weakened. **274 host tests passed in 128.542 seconds.**

Queries of the compiled policy confirmed the owner is a native `domain`/
`coredomain`/`netdomain`, not `appdomain`; the coordinator is separate. The scoped
home-execution, coordinator protection and cgroup-write assertions passed. An
intentionally false assertion forbidding the owner's own-home execution failed,
confirming the query oracle. The existing userdebug `su` permissive domain was
reported; neither new Andrix domain is permissive and no `su` execution is used.
These are compiled artifacts, not runtime enforcement proof.

The module-only stage did not regenerate the image's identity files; their stale
empty contents were recorded, not accepted as an owner identity. Full image
construction must produce and verify the actual system_ext UID/group records and
all matching image/host inputs before any launch.

The first full image (`9e08ea3`) subsequently built in 222.350 seconds; 27 images
and both host packages were frozen/rehashed. The actual image contains UID/group
7500 records and unchanged Vanadium/AppStore/APEX/shell bytes. APK review verified
both version1 console/negative packages under the existing non-platform lab signer;
initial observer mistakes about the aapt2 field name and zipalign flags remain.

The first offline guest booted, but the host core observer correctly failed with
exit127 because its stager omitted the required `host_elf.sh` dependency. The guest
also independently exposed a new-layer omission: `andrixd` entered UID7500 and its
correct enforcing domain but could not **read** `memory.max`. Its admission check
therefore did not succeed. The repair adds only read/open/getattr for the new
components' resource inspection, not cgroup write authority or a skipped check.
No owner shell/UI/P5/negative probe was reached in that window. Runner, stop and
capture cleanup exited0; controllerFAIL and all evidence were retained. The
51-file closed window contains17,093 offline packets with zero reported drops,
not a privacy or owner-runtime pass.

The corrected `dad4d16` image built in 319.710 seconds. Its fresh offline window
passed the core check and P5 ordinary-app isolation/uninstall. A disposable PIN
was set through normal setup; fingerprint/face enrollment was declined visibly.
After normal reboot, user0 was `RUNNING_LOCKED`, the CE-prepared flag was absent
and `andrixd` was not running. Normal PIN entry changed Android to
`RUNNING_UNLOCKED`, published CE availability and started the non-root service,
which reported successful resource admission. This does not claim an independent
native cryptographic-key-status measurement.

The console still failed before `ActivityThread.attach`: its new SELinux domain
lacked the **standard app API service-discovery rule**, producing an `activity`
lookup denial and startup exception. The next correction supplies the same
`app_api_service` discovery available to ordinary apps, not system API discovery,
a platform signature or Android permission grants. No owner shell or dedicated
owner-access negative was reached. All controllers/runner/stop/capture exited0;
that cleanup result is not a console PASS. The 2,045-file closed window retains
81,858 offline packets/zero reported drops and the console failure. Vanadium and
the existing Android security boundaries remain unchanged.

## Evidence

New private evidence is selected by `out/owner-session/EVIDENCE`; the earlier
7,217-file connected-preparation seal is immutable. Initial I13 review was
cancelled without substantive findings; primary source inspection supplies this
plan. The first source-review pipeline hit SIGPIPE through `head`; the failed
observation and corrected bounded reads are retained. No guest has started for
this milestone at plan creation.
