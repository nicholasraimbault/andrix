# Ordinary principal reference experiment

Status: bounded diagnostic plan and source vehicle, with two partial emulator results.
Host parser checks, public SDK compilation and artifact verification passed. Runtime established
standalone context creation and entry controls. A fresh diagnostic then localized an operation
package mismatch in the probe's binding, not a missing notification grant. Notification delivery
and a production launch profile remain unqualified.
No production principal mechanism or key policy is selected. This plan authorizes no
personal phone operation, personal key provisioning or change to verification policy.

The [mechanism comparison](2026-09-24-integration-mechanism-assessment.md) separated principal
representation, API binding and execution lifetime. This experiment tests an existing Android
recognized package/UID as a reference subject before introducing a new framework principal.
It does not require an APK for each future owner program.

## Question and limits

Can a process launched independently of an APK UI use that ordinary subject's Android
notification policy, with correct denial, grant, attribution and revocation? If a required
check refuses, which layer actually refused it?

The vehicle uses the platform's existing debug launcher, not a new privileged execution API.
The pinned `system/core` source at `84ebea5e21110f31b632473a2fdb1c656b599b24`,
`run-as/run-as.cpp:203–312`, checks the shell/root launcher, resolves package metadata,
requires a debuggable package, validates its data path, changes credentials and selects a
`fromRunAs` context before execution. The payload is not meant to run with the launcher's
shell/root identity.

The selected `system/sepolicy` revision `87a06ed71fd67cff9f77feaa9ae3504edb5d0972` maps this
to `runas_app`. That is an app/debug domain with extra debugging access, not the final Andrix
owner domain. A pass would not qualify a production launcher, general MAC isolation or native
work supervision. Record the actual context and capabilities, not just a successful `run-as`.

`PrincipalCommand` runs through `app_process`. Its private `ActivityThread` and per-user context
bootstrap is tied to the inspected framework revision. The bootstrap does not change kernel
credentials, and Binder services must still check the real caller. It may be blocked or
incompatible. Do not disable hidden API enforcement, alter the class loader's trust, relabel
files or change SELinux enforcement to obtain a positive. Such a failure identifies an API
binding problem, not automatic proof that the principal model is impossible.

This is an ART command diagnostic, not qualification of a complete native C binding. A future
same-principal binding or an explicitly delegated platform service has a separate contract.

## Inputs and subjects

The [source vehicle](../tests/native-principal/README.md) supplies:

| Subject | Purpose |
| --- | --- |
| `dev.andrix.proof.principal` | Ordinary debuggable package, declared notification and location permissions |
| `dev.andrix.proof.principalpeer` | Separate debuggable UID with independently denied/granted policy |
| `dev.andrix.proof.principalclosed` | Nondebuggable package that the debug entry should refuse |

Use exact inspected APK bytes with a disposable ordinary developer identity. No shared UID,
privileged package flag, platform permission, service, receiver or automatic background process
is requested by the fixture. Location permissions are declarations for later coverage; this
first command does not request or report location data. No real coordinates are captured.

Start from fresh disposable emulator state with qualified image provenance. Do not reuse a
consumed guest, queue or operation identity. Record the source snapshot, complete bundle,
certificate, manifest flags and expected package identities before install. Passing this
experiment does not promote the debug route into product architecture.

## Host preparation

1. Check argument bounds, UID/GID tuple parsing, capability refusal, security context checks
   and malformed observations with the plain Java host test. Include privileged appIds encoded
   under a secondary user: a large full UID is not sufficient proof of ordinary authority.
2. Compile all Java against the selected public SDK. Preserve failures separately; this does
   not exercise reflective private APIs.
3. Package and independently verify all APKs. Check exact package/version/certificate,
   permission declarations, lack of shared UID and the intended debug flag differences.
4. Freeze source, tools, artifacts and controller inputs. Admit actual storage, memory and
   execution resources before a new guest. Host compilation does not waive VM admission.

## Runtime sequence

### Establish the subjects

Install the three exact packages. Resolve their UIDs and code paths through Package Manager,
then compare installed bytes and signatures with the expected artifacts. Confirm distinct
ordinary appIds and declared permission states. The package path is observed, not reconstructed
from a guessed data directory name.

Before any command effect, require its four UID and GID values to match the actual process,
an ordinary appId, zero effective/permitted/inheritable/ambient capabilities and the expected
`runas_app` context. Preserve supplementary groups, bounding capabilities, seccomp and cgroup
observations as evidence. They are not replaced by the package label or by UID display text.

Check that no package UI process is providing the claimed independent execution. The optional
permission activity can affect the entire UID's foreground treatment. Close it and inspect
actual ActivityManager/UID state before making any background claim. A sleep duration is not
that evidence. Framework package bookkeeping caused by context creation must be recorded.

### Exercise ordinary notification policy

For a fresh exact nonce and notification ID:

1. Establish denied `POST_NOTIFICATIONS`, then attempt the ordinary post. Record the actual
   permission state and absence of the exact notification. An API return alone is not a pass.
2. Use Android's real permission UI or explicitly labelled privileged test setup to grant the
   permission. State which path was used; setup through a shell is not native consent UI proof.
3. Post a distinct exact nonce. Require the correct package, UID, user and tag in service state,
   then observe the UI where appropriate. Exclude media, call and foreground service exceptions.
4. Observe independently of the APK UI process. Notification retention in a system service is
   not proof of retained native computation or wake authority.
5. Cancel the exact notification, verify absence, revoke the grant and attempt another fresh
   declared post. Distinguish permission denial from channel policy, service failure and
   context bootstrap failure.

Negative controls must reach their intended layer:

- `run-as` refuses the nondebuggable control before payload execution.
- A root/shell/system payload invocation is refused by the probe's identity guard before a
  phone API is called. Never use that invocation as the capability positive.
- The peer UID claiming the principal package is refused by package/caller validation.
- A process for the wrong Android user does not borrow another user's package/grant.

A local context lookup failure is not a successful Binder authorization negative. Keep a
same-subject positive control with each relevant refusal so a broken binding cannot pass.

### Repeat for another Android user

Create only a fresh disposable full user. Record its actual user identity and incarnation,
package installation, UID mapping, CE availability and running/foreground state. Repeat the
reference without treating a changed HOME as a new user or assuming a package installed for
one user is installed for all users. Stop and remove only the user created by this trial,
after all its owned command processes and observations are closed.

This does not establish VPN enforcement, Doze, attribution for other capabilities, battery
accounting, complete user deletion safety or general owner account support. Location streaming
and foreground-only access remain a deciding next case, with a test provider and separate
privacy/revocation oracles. Never extend a notification result to those paths by analogy.

## Uncertainty, cleanup and records

Capture an operation identity before a mutating command. If transport is lost after a post
or cancel may have been accepted, retain that exact nonce and reconcile service/process state.
Do not issue the mutation again under a new identity. Read only observation can be used to
reconcile; failed observation is not proof of absence or retirement.

End only the captured command process or its owned execution scope, and verify actual exit.
Do not signal a later process through a guessed/reused PID. Cancel exact owned notifications,
then uninstall the exact fixture packages after their commands retire. Record unsuccessful
cleanup honestly and retain unresolved identities. A complete guest shutdown is a separate
containment observation, not retroactive proof that an earlier per-command Stop worked.

Use bounded private diagnostic records with no credentials, raw private files or location
contents. Do not turn the fixture's JSON observations into a product activity logging default.
A source/compiler/artifact result and an Android runtime result remain separate outcomes.

## Initial runtime result

The first fresh emulator run used APK source `cbe739e` and observer source `d4923a4` against
the previously qualified image lineage. Three exact APKs installed with distinct ordinary
application UIDs and matching installed bytes. No fixture Activity was started, and no APK
process was observed before the standalone commands.

Both debuggable subjects ran the ART command with matching real/effective/saved/filesystem
UID/GID tuples, zero effective/permitted/inheritable/ambient capabilities and the expected
`runas_app` context. Each obtained its own package context, application UID, target SDK and
notification permission state. The nondebuggable entry refused execution, and the command's
identity guard refused a direct shell invocation before capability use.

This was not a normal application launch profile. The observed commands retained shell
supplementary groups, the inherited launcher cgroup placement, a nonempty bounding set,
`NoNewPrivs=0` and `Seccomp=0`. The pinned `run-as.cpp:147–163` explicitly retains the caller's
supplementary groups and adds the shared application group. Do not describe the debug entry
as a sanitized production account transition or infer power/foreground behavior from its UID.

The notification channel creation call returned. The first denied-permission attempt then
reported `java.lang.SecurityException` in the probe's `post` phase. In that tested APK, the
phase covered both notification construction and submission, and the probe recorded the
exception class but not a useful origin. The trial stopped there. No grant positive, notification
service observation, foreign-package post, revocation or secondary-user control was reached.
The exception alone is not a qualified `POST_NOTIFICATIONS` denial or proof of a failed
principal model.

SELinux remained enforcing. Startup logged policy denials for some private framework resource
operations, but those logs do not establish the exception's cause. No hidden API, permission,
MAC, verification or foreground checks were disabled. The three package uninstall operations
returned success. Cuttlefish, its runner and packet capture stopped, and the disposable RAM
backing disappeared. The matrix result remains **incomplete**, with its original failure
retained separately from cleanup success.

The follow-up source now separates construction from submission and records bounded
attribution and exception diagnostics. It passed the same fifty host guard checks and public
API 36 compilation. That is not a follow-up runtime result. The next attempt must obtain a
same-subject granted positive before classifying a denied request. It must use fresh guest state and preserve the debug-profile limitations.
It must not reinterpret the first result as a permission pass or change policy to obtain one.

## Diagnostic runtime result

A second fresh guest used diagnostic source `01da2ca`. The same entry controls and standalone
context queries behaved as before. Explicit privileged fixture setup granted
`POST_NOTIFICATIONS`, and the command observed that grant as true. Notification construction
completed, but actual `enqueueNotificationWithTag` still failed with:

```text
Caller android:10146 cannot post for pkg dev.andrix.proof.principal in user 0
```

The diagnostic recorded actual UID and attribution UID `10146`, package context
`dev.andrix.proof.principal`, but **attribution package `android`**. This is a binding defect,
not evidence that the permission grant was missing. The native service refused the mismatch;
it did not grant the ordinary UID the system package's identity.

The source explains the behavior at framework revision
`aab06a8bd44c4c2b58eeec780fde83baa9d43a40`:

- `ContextImpl.createPackageContextAsUser`, around lines 3147–3153, creates a context using
  the existing context as its container. Around lines 3975–3980, that constructor retains
  the container's base/operation package. Creating package resources from a system context
  therefore does not construct the principal's own operation identity.
- `NotificationManager.notifyAsUser`, around lines 937–945, passes both the context package
  and operation package to the service.
- `NotificationManagerService.resolveNotificationUid`, around lines 10150–10174, checks
  package/UID ownership and valid delegation. The observed exception matches its refusal.

Both attempts remain incomplete for notification delivery, revocation, foreign-package and
secondary-user controls. Both ended with exact fixture uninstall acknowledgements, an unchanged
boot and enforcing policy, and closed VM/runner/capture processes. No policy checks were disabled.
The first ambiguous result is retained, not retrospectively relabelled as this diagnosed result.

The next reference binding must construct the actual principal's operation identity from
native authoritative package/UID state. It must expose that identity for observation and keep
service-side ownership, attribution and revocation checks intact. Merely obtaining another
package's resources, overriding an identity label or granting more permissions is not a
production integration contract. A private framework factory may be another diagnostic vehicle,
but it is not a stable native API or an accepted production mechanism by itself.

## Promotion condition

Only the observed identity, notification policy and UI/command separation can be qualified
by this vehicle. Record which current mechanisms worked, which refused and which required a
new binding or framework contract. A successful debug route is evidence for a principal
representation candidate, not a substitute for the final owner entry, supervision and policy
integration design.
