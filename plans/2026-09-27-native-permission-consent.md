# Real Android consent reference

Status: Android popup, grant, independent command use, peer isolation and denial controls observed.
A Settings revoke took effect, but the grant was present again after a cold boot without another
controller grant input. Its cause remains under investigation, so persistent revocation is not
qualified. The [installer diagnosis](2026-09-27-package-installer-durability.md) and all earlier
failures remain retained. This extends the
[ordinary principal reference](2026-09-24-native-principal-reference.md) using Android's real UI,
not privileged test grants. It selects no production account broker, native entry or permission
default.

## Observed checkpoint

The normal image from `cac0ba6` retained the original probe APKs, UIDs and exact bytes through cold
boots without reinstalling them. Android's ordinary notification dialog then granted the principal
probe `POST_NOTIFICATIONS`, with `RUNTIME_GRANTED` and `USER_SET` in the permission service. After
the helper Activity closed, the UID left `TOP`. An independently launched command posted under
that UID, and the complete notification service protobuf contained the exact owned record. The
peer stayed denied and could not post as the granted package.

The peer's Back control left grant state and flags unchanged. Its first denial set `USER_SET`,
without `USER_FIXED`. A later real Allow enabled its independent command too. False package
attribution was refused even when both subjects held their own grants. The nondebuggable control
received two real denials, setting `USER_FIXED`. A fresh Activity instance then received a new
denied callback with unchanged flags and no selectable permission prompt observed. This was not
continuous display recording, and the callback was not used as the permission authority.

Default accessibility root queries sometimes returned null. The standard all windows query
provided the focused PermissionController hierarchy within the same bounded observation budget.
No tool status, accessibility setting, animation, timeout, SELinux or permission guard was relaxed.
A prior interrupted request remains historically unknown. Its entire guest scope was retired,
current denied state was reconciled, and the later successful request was explicitly new, not a
replay or a claim that the original never happened.

A single observed Settings main switch action withdrew the principal's grant in the permission
service. Android logged a cached app process kill with `PermissionHelper` and cancellation of its
owned notification. A later UI corroboration failed, so the trial did not complete its remaining
notification and peer bookends. On the next cold boot, the principal was granted again, while peer
and fixed denial states were unchanged. The next controller stopped before any new input. Read only
inspection subsequently found both current permission files agreeing with that grant. No reset,
reinstall, data repair or new grant input was used. This does not yet distinguish storage loss from
a later Settings or permission writer action.

A separately recorded withdrawal attempt then sampled the raw main and reserve files before the
stop. Both were replaced with identical revoked records. A read that raced the replacement remains
labelled unstable, rather than being promoted by a later decode. The final live sample was denied
16.6 seconds after input. There was no additional UI query, guest decoder or forced sync in that
window. Early in the next boot, before boot completion, both original new inodes, bytes and file
timestamps were retained. Android's live state and the decoded files were denied. This sampled
attempt retained the withdrawal. It does not repair the earlier failure or establish its cause.
Checkpoint call counters changed during the write window, but do not prove when a checkpoint
completed. General revocation durability and the complete permission lifecycle remain open.

The separate key and canary controls survived throughout. Native execution and factory entry stayed
disabled. Debug `run-as` and the private ART reference are still not a production native entry,
maintained API, human presence proof or account lifecycle implementation.

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
makes the new-subject precondition false. Later controls retain those same installed subjects and
their complete request history; they are not described as fresh. The interrupted request above was
followed by captured whole guest retirement and read only reconciliation before a separately
issued lab request. Its unknown historical outcome was not converted into cancellation or success.

No `pm grant`, privileged revoke, AppOps override, permission flag reset, app data clearing or
reinstallation is used to manufacture the consent states. Synthetic UI input is permitted lab
control, not proof of human presence. Read only privileged observation remains diagnostic.

## Finite matrix

1. Establish distinct ordinary UIDs, installed bytes/signers, target SDK and denied notification
   state. A fresh post must have no exact active notification. Keep the closed package entry and
   direct shell payload refusal controls.
2. Open the principal's own Activity. Locate its request button and the real PermissionController
   window by actual UI identity and content. Confirm the named subject. Grant using the system UI.
3. Verify Android's current grant and flags independently. Persistence is a separate check.
   Close the probe Activity and observe that it no longer supplies TOP state. A fresh command post must then be attributed to the correct
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
