# Notification preference setup route

The selected preference is unchanged: channel allow bubbles 1 with exactly user lock bit 256,
under the original package and UID. A missing preference, a default -1/0, or the old command's
1/0 is refused. This proves retention of a genuine stored user preference, not bubbles delivery.
The channel is never recreated or updated by observation. No notification is posted.

The transition below is supported by inspected source, not an Android runtime result. The
ordinary shell command entry, non SDK reflection availability, Binder/SELinux admission, actual
mask, persistence and every dump form still need calibration on a disposable guest. A command
acknowledgement alone establishes neither the preference nor its durability.

All Android references are under the pinned `frameworks/base/` root. N below means
`services/core/java/com/android/server/notification/`. Ten source identities are pinned in
setup-api.json and checked before any producer output, then again at build closure.

## Candidates and decision

1. **Built in channel command, rejected.** `cmd notification set_bubbles_channel` obtains the
   local binder stub at `N/NotificationShellCmd.java:123-130`, returned directly by
   `N/NotificationManagerService.java:3339,4181-4182`. Its getter forwards to PreferencesHelper,
   `5454-5474`. That returns the stored channel object, not a copy,
   `N/PreferencesHelper.java:1508-1522`. The command mutates it in place before calling update,
   `N/NotificationShellCmd.java:317-322`. Old and updated channels are therefore already equal
   when the user change detector compares them. This route yields allow bubbles 1 with lock 0,
   not a user locked preference. It must not appear in the setup command ledger.
2. **Package bubble preference, rejected for this oracle.** `cmd notification set_bubbles P 1 0`
   really is a scalar user setting. The command passes the preference, not a mutable channel,
   `N/NotificationShellCmd.java:291-306`. NMS permits shell and requests persistence,
   `N/NotificationManagerService.java:4805-4809`. PreferencesHelper directly assigns the value
   and ORs USER_LOCKED_BUBBLE, `N/PreferencesHelper.java:850-856`; that package bit is 2,
   `198-204`, and its default value is NONE, `184`. XML writes allow_bubble and
   app_user_locked_fields, `792-797`, and reads them at `358-390`. However, the normal text
   package dump omits both package bubble fields, `2330-2422`. The proto dump at `2424-2477`
   and JSON dump at `2705-2796` omit them too. The printed package userSet flag refers to the
   POST_NOTIFICATIONS permission, not bubbles. Adopting this setting would lose the current
   direct dumpsys preference oracle or require a further read endpoint. It is not selected.
3. **App channel update, rejected.** The subject's create/update path is not a user setter.
   Creation resets allow bubbles and clears locks, `N/PreferencesHelper.java:1192-1203`;
   a nonuser update clears locks at `1302-1307`. It would also violate observation's separate
   read only call graph. No new operation is added to the ordinary APK.
4. **A separate ordinary shell command with an explicit copy, selected.** Fetch through the
   remote notification interface, make an independent Parcel copy, mutate only that copy and
   submit it to the existing shell permitted user update. This leaves the strong 1/256 dump
   and persisted oracle intact. The code refuses root, app UID, local interface, missing channel,
   preexisting preference and copy aliasing. It cannot succeed through the rejected alias path.

The separate command is a dex jar, not another APK, service, image module or product change.
It does not adopt permissions, switch UID, disable API checks or enter the target app's process.
Its only selected state effect is one fixed channel update. It is setup only, never an observer
and never a way to enter a deferred UID. Other channel fields are left unchanged.

## Full selected path

### 1. Fixed command identity and request

The producer emits B2NotificationSetup.jar separately from the six class subject APK. Freeze
its actual hash from setup-artifact.json and capture it at the fixed guest path before the first
selected effect. The setup ledger requires a setup_jar provenance capture. Verify the file hash
again before and after its one issue. Do not use a new jar merely because its filename matches.

Step 4 from `setup_commands(contract, initialize_nonce)` is exactly:

```text
env CLASSPATH=/data/local/tmp/andrix-b2-notification-setup.jar \
  app_process /system/bin dev.andrix.proof.b2setup.NotificationSetup \
  A NONCE SETUP CONTRACT_SHA256
```

A is the independently captured UID, 10000..19999. The other arguments are the owned initial
nonce, setup and exact H, not values copied from a later reply. H now includes the setup route
identifier channel-bubbles-copy-v1. Old contract bytes cannot be silently reused.

`NotificationSetup.run` checks Process.myUid() equals 2000 before Binder access. UID 0 and the
subject UID are refused. The command is launched by ordinary shell, without su or run-as. Native
app_process dispatch to RuntimeInit is at `cmds/app_process/app_main.cpp:79-88,335-338`;
`core/java/com/android/internal/os/RuntimeInit.java:351-367` finishes that tool startup. This is
not an application bootstrap or a change to the subject's execution identity.

### 2. Obtain a remote interface and a separate object

The command uses existing ServiceManager.getService("notification") via reflection. That public
non SDK method's lookup is at `core/java/android/os/ServiceManager.java:148-161`. It then uses
INotificationManager.Stub.asInterface and the two fixed interface methods. Signatures are at
`core/java/android/app/INotificationManager.aidl:110,113`. No transaction number is guessed and
no locally constructed NMS stub or implementation is linked into the jar.

The command requires a live Binder and queryLocalInterface(DESCRIPTOR) == null. In this pinned
BinderProxy, local compatibility interfaces can exist, so a nonnull result is conservatively
refused too; see `core/java/android/os/BinderProxy.java:546-564`. This command must not be run
inside system_server. Its own UID check also prevents that normal UID 1000 process from passing.
Non SDK resolution or access failure is an explicit failed setup issue, not permission to add
an exemption or retry. It can fail before the setter; guest admission remains unqualified here.

Remote getNotificationChannel is called with com.android.shell, user 0, fixed P and channel ID.
NMS accepts shell at `N/NotificationManagerService.java:5461-5474`, resolves the package's actual
UID and obtains the channel. The original stored object remains inside NMS. Independently of
that transport separation, the command always clones its received channel with writeToParcel,
setDataPosition(0) and NotificationChannel.CREATOR.createFromParcel. CREATOR constructs a new
object at `core/java/android/app/NotificationChannel.java:1630-1635`. The constructor reads
lock and allow bubbles at `350-396`; the writer emits those fields at `428-483`.

The command requires the pristine fixed channel, false canBubble, printed allow bubbles -1 and
lock 0. Its toString scalar checks are extra setup guards, not a new primary oracle. It also
checks the copy is a different object with identical initial printed fields. It changes only
that copy, then proves the original has not changed. If clone bypass or aliasing occurs it
refuses before submitting an update.

### 3. Existing authorized user update and comparison

setAllowBubbles(true) changes mAllowBubbles to 1, without setting a lock itself,
`core/java/android/app/NotificationChannel.java:872-874`. The command calls the fixed remote
updateNotificationChannelForPackage once with P, A and its copied channel. It never calls the
app createNotificationChannels route. NMS permits shell at
`N/NotificationManagerService.java:5606-5611,13473-13482`. No root authority is used even though
the platform also permits root there.

NMS forwards to updateNotificationChannelInt, which requests fromUser=true at `3977-3981`.
PreferencesHelper loads the existing stored channel, inherits its locks and compares it with
the separate update at `N/PreferencesHelper.java:1283-1304`. The old value remains -1; the
copied update is 1. lockFieldsForUpdateLocked therefore ORs USER_LOCKED_ALLOW_BUBBLE,
`2274-2301`, bit 0x100 in `core/java/android/app/NotificationChannel.java:252`. No other selected
field changes. The updated object replaces the stored one at `N/PreferencesHelper.java:1314`.
This path does not rely on changing a stored object before comparison.

The fixture uses a custom channel, not the default channel. Consequently the default channel
permission synchronization branch at `N/NotificationManagerService.java:3982-3984` is not its
route. POST_NOTIFICATIONS is still independently checked with permissionmgr and must not change.

### 4. Persistence and defaults

NMS requests policy saving at `4007`; handleSavePolicyFile queues it after 250 ms at `1451-1454`.
SaveFileRunnable writes through AtomicFile at `1465-1505`, calls writePolicyXml with forBackup
false, and finishes the write. The root/ranking writers are at `1511-1527` and
`N/PreferencesHelper.java:714-840`. Package UID and channel IDs are preserved in this ordinary
on disk form. Channel XML writes locked="256" at
`core/java/android/app/NotificationChannel.java:1427-1429` and allow_bubbles="1" at `1448-1449`.
The reader restores them at `1322,1325`. Zero locks are omitted and a missing bubble field means
-1, not 1. Pruning the preference or restoring a default is therefore visibly different.

No helper acknowledgement promises these asynchronous bytes have settled or are durable.
Complete stable primary/reserve/backup captures, owner service read back and the clean setup
reboot remain mandatory before native staging. Never force read-settings or write-settings.

### 5. Android primary oracle and refusal cases

The unchanged primary tool is `dumpsys notification --noredact --package P`. Exact UID and
package section output comes from `N/PreferencesHelper.java:2305-2392`, bounded by the next
section at `N/NotificationManagerService.java:8780-8784`. Complete channel printing is at
`core/java/android/app/NotificationChannel.java:1704-1752`. Locks print hexadecimal without
0x, so the retained row must contain mAllowBubbles=1 and mUserLockedFields=100. Stored XML uses
decimal 256. This is not the package permission derived userSet text.

Both parsers default to stage='retained', requiring exactly that 1/256. stage='created' is only
the prior -1/0 setup precondition; stage='absent' is only pristine baseline. The old in place
1/0 result fails all three stages. A reset -1/0 cannot qualify retained state. Missing channel,
wrong UID, deleted state, a changed baseline field or duplicate identity still fails.

The new command prints a bounded challenge/scope acknowledgement with stage=update_returned,
setter_calls=1 and state_proven=false. observations.notification_setup validates it strictly,
but it cannot replace either Android owner oracle. No acknowledgement claims a user lock.
The subject's later challenge bound key/canary answers also remain secondary for this state.

## Host checks and guest limits

Python tests submit the rejected old 1/0 and reset -1/0 to both final parsers. They also reject
stale or malformed setup acknowledgements, wrong UID/root, extra fields and the old argv.
The strict retained mask is not relaxed. The stored parser continues to reject omitted/zero
locks and a reset preference, while recognizing defaults only in the explicit setup stage.

The separately bounded JVM tests compile the actual NotificationSetup source against test only
classes generated in scratch. Their manager deliberately returns a stored alias even for its
fake remote interface. An explicit copy yields 1/256 in the selected comparison model; the old
in place mutation yields 1/0; bypassing the clone is refused before mutation. Root/app UID,
local/missing binder, old preference and malformed arguments are refused. Those are host object
model checks, not an NMS, Binder, Parcelable codec, ART or Android persistence qualification.

The SDK build separately compiles the command against the real pinned public android.jar and
checks its one DEX definition. Test classes cannot enter either artifact. All non SDK entry,
actual permissions/SELinux, serialization, channel update, complete dumps, settled policy XML,
reboot, suspension, lift and image reversal remain disposable guest gates. No Android action
was run to claim them here. If any gate fails, preserve that guest and stop without repair.
