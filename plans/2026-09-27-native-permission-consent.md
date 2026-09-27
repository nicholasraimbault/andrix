# Real Android consent reference

Status: bounded vehicle prepared, but no permission popup or grant has been qualified. The
[installer durability diagnosis](2026-09-27-package-installer-durability.md) interrupted the trial
before any UI request. The failures and later read only controls are retained. This extends the
[ordinary principal reference](2026-09-24-native-principal-reference.md), aiming to replace labelled
privileged test grants with Android's own UI for one permission. It does not select a production
account broker, native entry or permission default.

## Question

Can the declared subject obtain `POST_NOTIFICATIONS` through Android's real permission dialog,
then use that grant from an independently launched command after its Activity closes? The grant
belongs to the package UID and Android user, not the command, Console or a new native consent table.

The existing probe Activity is a useful test subject. Its ordinary request path identifies the
requesting Activity's package. PermissionController presents and changes that package's grant
through the real permission service. A command without an Activity does not gain a caller token
by supplying a package string.

The system server `REQUEST_PERMISSIONS_FOR_OTHER` route remains a separate unqualified candidate.
Neither a source comment nor a shell invocation establishes its caller restriction or a trusted
broker. It is excluded from this vehicle. No hidden API, signature, SELinux or background policy
check is weakened.

## Scope and inputs

Use the exact ordinary principal, peer and nondebuggable control APKs, independently verified
before installation. The retained normal reader guest may provide the disposable environment
only if these are fresh package subjects there, its owned continuation fits the unchanged resource
budget, and the existing identity/key canaries remain protected. Use fresh requests and nonces.
Do not reset retained userdata or replay initialization. Any inherited state of a test package
makes the new-subject precondition false.

No `pm grant`, privileged revoke, AppOps override, permission flag reset, app data clearing or
reinstallation is used to manufacture the consent states. Synthetic UI input is permitted lab
control, not proof of human presence. Read only privileged observation remains diagnostic.

## Finite matrix

1. Establish distinct ordinary UIDs, installed bytes/signers, target SDK and denied notification
   state. A fresh post must have no exact active notification. Keep the closed package entry and
   direct shell payload refusal controls.
2. Open the principal's own Activity. Locate its request button and the real PermissionController
   window by actual UI identity and content. Confirm the named subject. Grant using the system UI.
3. Verify Android's stored grant and flags independently. Close the probe Activity and observe that
   it no longer supplies TOP state. A fresh command post must then be attributed to the correct
   package, UID, user and operation package in notification service state.
4. While that subject is granted, the peer remains denied. Its own post fails, and claiming the
   granted package is refused at the real service. Give the peer its own later positive control.
5. Revoke through the actual Android permission settings path. Record that path, grant/flags,
   notification state and captured process outcomes. New posts must fail. Process termination is
   observed, not inferred or generalized to every settings toggle.
6. Exercise denial, Back cancellation and later grant using distinct owned requests. Do not infer
   the button pressed from a returned denied value. Repeated denial may make the permission
   unrequestable; verify the flags and absence of a new dialog without changing them by shell.

Each UI input requires a unique observed target and an owned queue entry. Wait for actual UI
readiness, not a guessed delay. An uncertain input or transport result retains the original request
and does not authorize another tap or a fresh request. Observe and reconcile before any continuation.
Exact owned notifications and command processes remain separately tracked and retired.

## Limits and later design

This qualifies neither visible notification delivery nor a complete native C binding. It retains
the debug `run-as` and private ART bootstrap limitations of the earlier reference. No native
factory or production account designation is enabled. It does not test location, one time grants,
other Android users, locked consent, user removal, hardware sensors or whole product power policy.

A later broker must bind authenticated work, native incarnation and Android user to actual platform
consent. Its request record is not a grant. An Activity can legitimately affect the whole shared
UID's foreground eligibility while it is visible; that effect must end with the real presentation.
No helper is kept alive to fabricate foreground permission for detached work.

Closing a dialog is not proof that no permission change remains queued. Account retirement needs
ordering at the permission authority, real disposition evidence and the retained UID hold. A late
reply, vanished window or reset boolean never proves retirement. If an Android revocation path
decides to kill the UID, its effect must reach native work through the real lifecycle join; the
behavior of each actual path still needs qualification.

The normal login's ordinary outbound networking remains the accepted default. This vehicle selects
no broader permission manifest, sensor default, role, administrative authority or automatic grant.
