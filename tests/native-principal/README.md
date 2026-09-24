# Native principal reference probe

A disposable diagnostic vehicle for the proposed
[native principal contract](../../plans/2026-09-24-native-principal-contract.md).
It is not a production launcher, principal representation or native C API.
See the [execution plan](../../plans/2026-09-24-native-principal-reference.md) for scope,
oracles and limits.

## Parts

- `PrincipalActivity` is an optional ordinary permission UI. It reports its actual package
  and UID, requests notification or foreground location permission only on button presses,
  and opens Android's application settings. It does not start or supervise command processes.
  Its visibility can affect the UID's foreground policy, so it must not stand in for evidence
  about independent background work.
- `PrincipalCommand` is an ART command invoked separately through the platform's `run-as`
  debug entry and `app_process`. Private framework bootstrap access may be unavailable.
  It must fail rather than change hidden API, permission, MAC or verification policy.
- `ProbeIdentity` checks this vehicle's observed ordinary application UID/GID tuple, zero
  effective/permitted/inheritable/ambient capabilities and `runas_app` label before using
  the capability. It records, rather than invents, the other kernel policy fields.
- `ProbeArguments` bounds the finite actions, package names, public nonce and observation
  interval. It is not an authorization API.
- `ProbeModelTest` checks the parsers and local guard on a host. It cannot establish Android
  identities, permission behavior, Binder access or UI delivery.

The three APK manifests use distinct package identities: a debuggable principal, a debuggable
peer, and a nondebuggable control. They share code but not a shared UID. The module definitions
are test helpers, absent from product package lists. Use disposable ordinary developer signing
identities, not an installation or platform key. The source does not contain private keys.

## Command protocol

The command takes:

```text
PrincipalCommand info|post|cancel|observe FIXTURE_PACKAGE PUBLIC_NONCE [OBSERVE_MS]
```

Only the three declared fixture package names are accepted. Each post uses the exact public
nonce as its notification tag and the fixture's fixed notification ID. The observation
interval is bounded. The command prints JSON lines with phases, actual identity observations,
context metadata and notification observations. It reads only its own fixed `/proc` paths;
it does not record arbitrary command arguments or environment contents.

`submission_returned` means the API call returned. It does **not** mean a notification was
posted, displayed or healthy. Observe the exact package/tag/ID separately through the command,
the authoritative service and the UI as applicable. The notification is an ordinary one,
not a media, call or foreground service exception. `info` does not test service acceptance.
A failed context lookup is a binding failure, not proof that Android rejected the native
principal's permission.

A conceptual invocation is:

```sh
adb shell run-as FIXTURE_PACKAGE --user USER_ID \
  env CLASSPATH=OBSERVED_INSTALLED_APK_PATH \
  app_process /system/bin dev.andrix.proof.principal.PrincipalCommand \
  post TARGET_FIXTURE_PACKAGE PUBLIC_NONCE
```

This is a description of the transport, not an instruction to run on a personal phone.
Resolve and verify the installed APK path and exact identity first. The Android user ID is
not a UID selector; `run-as` resolves the installed package metadata. A foreign target package
is used only as a declared negative control. Never replay an uncertain post under a fresh
nonce merely because the transport did not return.

## Host checks

The pure helpers need only a JDK. Compile `ProbeArguments.java`, `ProbeIdentity.java` and
`ProbeModelTest.java` into a fresh output directory, then run
`dev.andrix.proof.principal.ProbeModelTest`. The output explicitly disclaims runtime evidence.
Use a bounded heap and execution deadline.

The complete Java source can be compiled against the selected public Android SDK. The private
framework lookup is reflective, so public SDK compilation does not prove that lookup will
succeed on a device. APK packaging, signatures, manifest identities and debug flags must also
be inspected before runtime. Soong module definitions and a manual SDK build are distinct
build paths; do not claim that testing one exercised the other.
