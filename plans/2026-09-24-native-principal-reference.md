# Ordinary principal reference experiment

Status: bounded diagnostic plan and source vehicle. Host parser checks and public SDK
compilation are preparatory evidence, not an Android permission or lifecycle result.
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

## Promotion condition

Only the observed identity, notification policy and UI/command separation can be qualified
by this vehicle. Record which current mechanisms worked, which refused and which required a
new binding or framework contract. A successful debug route is evidence for a principal
representation candidate, not a substitute for the final owner entry, supervision and policy
integration design.
