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
- `ProbePrincipal` checks that Package Manager resolves exactly one fixture package for
  the actual process UID, that its application metadata matches that full UID, and that
  context and operation attribution agree. These are local consistency checks, not grants.
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

Only the three declared fixture package names are accepted. The argument selects the target,
not the caller. The caller's principal is resolved independently through Package Manager and
the actual UID. Info, cancellation and observation require the caller's own target. A foreign
post uses Android's documented `notifyAsPackage` delegation entry as a negative control, with
no delegate grant configured. An unexpected return is not reported as a successful refusal.
Each post uses the exact public nonce as its tag and the fixture's fixed notification ID. The observation
interval is bounded. The command prints JSON lines with phases, actual identity observations,
context metadata and notification observations. It reads only its own fixed `/proc` paths;
it does not record arbitrary command arguments or environment contents. The diagnostic
follow-up distinguishes construction from submission and bounds an exception message to
512 characters and its origin to twelve class/method/line frames. This is only for the
fixed-input disposable fixture, not a product logging policy.

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

The pure helpers need only a JDK. Compile `ProbeArguments.java`, `ProbeIdentity.java`,
`ProbePrincipal.java` and `ProbeModelTest.java` into a fresh output directory, then run
`dev.andrix.proof.principal.ProbeModelTest`. The output explicitly disclaims runtime evidence.
Use a bounded heap and execution deadline.

The complete Java source can be compiled against the selected public Android SDK. The private
framework lookup is reflective, so public SDK compilation does not prove that lookup will
succeed on a device. APK packaging, signatures, manifest identities and debug flags must also
be inspected before runtime. Soong module definitions and a manual SDK build are distinct
build paths; do not claim that testing one exercised the other.

## Corrected reference binding

The initial package-resource wrapper retained its system container's operation package.
The corrected vehicle resolves the actual UID's single fixture package, obtains matching
application metadata, uses `ActivityThread.getPackageInfo` with resource access but no code
inclusion, and calls the private `ContextImpl.createAppContext` factory with two arguments.
The factory has no inherited system container and no supplied operation package override. Context and
attribution UID/package must agree before any notification operation.

Reflection permits Java package visibility for this diagnostic factory. It does not install
ART hidden API exemptions, request `CONTEXT_INCLUDE_CODE` or `CONTEXT_IGNORE_SECURITY`, use
`getPackageInfoNoCheck`, overwrite identity fields or alter native grants and caller validation.
A lookup or access failure stops the vehicle. This is a diagnostic for the inspected framework
version, not a public SDK or production Andrix API contract. The corrected source passed 68 host guard checks
and public API 36 compilation before packaging; those are not runtime qualification.

## Preparation checkpoint

Fifty host parser and guard checks passed. The three ordinary APKs were then built from
source revision `cbe739e` and verified with the expected disposable certificate, exact package
and permission declarations, debug flag differences, one optional Activity and no shared UID,
service, receiver or provider. At the selected SDK 37 verification point, v3 verified. No Android
execution or Soong module build result is implied.

The standalone build used finalized public API 36 stubs and the selected R8/D8 prebuilt with
code generation floor 36. All used public API symbols compiled. The manifests still require
and target API 37; no application target or platform policy was lowered. Compile inputs,
code generation compatibility and runtime target are distinct facts.

The initial packaging attempt exposed an older D8 copy in the SDK tools tree. A later observer
also assumed the wrong `aapt2 dump` field names and boolean representation. Corrected tooling
and inspection were separate attempts with their original failures preserved. Use the pinned
build system's compiler and the actual tool schema, not a filename or guessed output format
as proof of compatibility. Reflective bootstrap and device policy remain runtime gates.
