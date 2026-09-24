# Native runtime route characterization

This is the first disposable comparison gate of the
[native integration proposal](../../plans/2026-09-24-native-runtime-integration.md).
The owner authorized experiments, not a production principal representation or personal
account provisioning. Source existence and artifact compilation are not runtime qualification.

One ordinary, nondebuggable APK declares a managed service and an isolated native service.
A finite instrumentation controller binds each, queries its own actual profile and keeps the
bindings for 30 seconds for independent platform observations. It then drops the proxies and
unbinds. Exact lifecycle logs distinguish returned unbind calls from remote callbacks. A 10 second window before instrumentation finish distinguishes unbind callbacks from
instrumentation's own final package force stop. A later explicit fixture force stop and uninstall
reconcile remaining processes, without claiming they caused an already observed exit.

The controller, managed service and native service have distinct processes. The controller and
managed service share the ordinary package UID. The native service must have an isolated UID
and MAC role, with no ART mapping. The managed service uses its real SDK context to construct
`KeyguardManager`, the construction that exposed missing authentic application shared state in
the earlier independent ART bootstrap. No fabricated state, reflection or hidden API exemption
is used here. Construction is not a credential or CE authority observation.

The native library implements only a read only Binder profile query. It reads bounded own
status, cgroup and MAC data and records only a boolean for `libart.so` in its own mappings.
It records actual Binder caller PID/UID. It does not accept paths, credentials, commands,
package overrides or caller identity claims. Lifecycle nonces are public test markers.

The fixture requests no Android permissions and has no Activity, receiver, provider, shared
UID, foreground service, wake lock or Internet permission. Instrumentation is privileged test
setup and changes Android process importance. The command explicitly denies test API access
and requires signature checking; it does not disable hidden API checks. **This is not a foreground policy comparison,
ordinary native work entry, native login, native API adapter or production profile pass.**
The isolated native route is not expected to receive the package's ordinary permissions.
This fixture makes no permission request and does not qualify that expectation.

## Observations and retirement

- Record installed package UID, manifest, ordinary signer and actual runtime flag observations.
  Read flags only. Never enable a disabled feature to claim the frozen image already supports it.
- Validate kernel UID/GID vectors, process identity, effective/permitted/inheritable/ambient
  capabilities, seccomp and MAC. Record groups, bounding capabilities, NNP and cgroup placement
  without promoting them to a production allowlist.
- Record authoritative activity/service state and independently readable process identities
  while both services are bound. An inaccessible observer is a limit, not proof of absence.
- Check managed attribution against the real package/UID. Check native isolation and actual
  caller separately. No API policy claim follows from a successful fixture Binder call.
- Require ordered create, bind, unbind and destroy records for each exact service instance.
  Unbind return alone does not acknowledge destruction. Destructor callbacks do not prove that
  a cached process exited. Reconcile both facts independently.
- Unknown install, binding or cleanup outcomes keep the original package/instance identity.
  Do not reissue as a fresh trial. A transport timeout is not a service refusal.
- Keep all failed artifacts/runs, use fresh guest state and preserve all original producer IDs.

`observe.py` checks structured instrumentation output and exact profile/lifecycle identities.
Native service callback logs are captured in binary form from logd. Writer PID and UID must
match the JSON identity; the records remain callback reports, not independent lifecycle authority.
Shell observations of the captured processes and ActivityManager records provide separate checks.
Unexpected/truncated replies, duplicate fields, silent callback loss and mismatched identities
must fail rather than create a pass.

The native library uses API 37 `ANativeService` and Binder NDK entry points. The platform header
explicitly documents a limited native service NDK subset. This gate does not claim arbitrary
NDK APIs work without ART. Soong definitions are supplied, but a standalone artifact build is
not a full Soong or ROM build qualification.
