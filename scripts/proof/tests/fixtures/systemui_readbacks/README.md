# Shell readback forms

These fixtures hold the shell outputs that the exact readback parsers in
`scripts/proof/systemui_sessions.py` accept. `forms.json` gives each form's device command, exit
status, standard error and origin. Each `<name>.out` holds the standard output byte for byte.
`scripts/proof/tests/test_systemui_readbacks.py` parses every form and derives the failing controls
from them: a truncated form, a reordered section or field, an extra field and an unexpected value.

An origin of `captured` means that the bytes, status and standard error were copied unchanged from
one guest capture. `source` means that they were derived from source, with illustrative values. A
source derived form may also carry `guest`, which records what a guest has shown of it:

- `form`: a guest capture has the same form. The same parser accepts it, with the fixture's status
  and standard error, and reads the same structure from it. The values differ, so the fixture stays
  source derived.
- `partial`: a guest showed some of the cases that the fixture holds. The form stays unqualified,
  and so do the cases that no guest showed.

A form with neither a capture nor a `guest` entry has not been shown by any guest.

## Captured forms

Captured forms come from the SystemUI component trials and the package verity trial on lab guests,
all on 2026-09-22. Each was copied unchanged from one owner service capture, which is a numbered
command with its standard output and error. Only the device command is kept. The host's `adb`
invocation and its paths were dropped. No output was edited.

| Fixture | Command | Source |
| --- | --- | --- |
| `listing-empty` | `pm list staged-sessions --only-parent` | Package verity trial, capture 0086, before any session |
| `listing-ready` | the same | Component trial 4, capture 0128, the wrong signer control ready |
| `listing-failed-signer` | the same | Component trial 4, capture 0233, that control failed at boot |
| `listing-ready-failed` | the same | Component trial 4, capture 0340 |
| `listing-failed-verity` | the same | Component trial 4, capture 0439, the missing sidecar control failed |
| `listing-applied-history` | the same | Component trial 4, capture 1279, variant C applied |
| `installs-historical-refused` | `dumpsys -t 25 package installs` | Component trial 4, capture 0094, the nonstaged control refused |
| `installs-active-ready` | the same | Component trial 2, capture 0126, a ready session in the active section |
| `installs-finalized-failed` | the same | Component trial 4, capture 0234 |
| `installs-finalized-two` | the same | Component trial 4, capture 0440 |
| `installs-finalized-historical` | the same | Package verity trial, capture 0521, the mismatched sidecar refused at commit |
| `path-factory` | `pm path --user 0 com.android.systemui` | Component trial 4, capture 0008 |
| `path-data` | the same | Component trial 4, capture 0670, variant A active |
| `digest-factory` | `sha256sum /system_ext/priv-app/SystemUI/SystemUI.apk` | Component trial 4, capture 0009 |
| `digest-data` | `sha256sum` of the active data copy | Component trial 4, capture 0671 |
| `fingerprint` | `getprop ro.build.fingerprint` | Component trial 4, capture 0667 |
| `boot-id` | `cat /proc/sys/kernel/random/boot_id` | Component trial 4, capture 0003. The trial read the boot ID in a combined command, and this is its third line. |
| `uid-list` | `cmd package list packages -U com.android.systemui` | Component trial 4, capture 0010 |
| `reply-create-staged` | `pm install-create --user 0 -r --pkg com.android.systemui --staged` | Component trial 4, capture 0124 |
| `reply-commit-ready` | `pm install-commit --staged-ready-timeout 60000 <id>` | Component trial 4, capture 0127 |
| `listing-pair-mismatched` | `pm list staged-sessions --only-parent` | Package verity trial, capture 0520, read just before `installs-finalized-historical` |
| `listing-pair-nonstaged` | the same | Component trial 4, capture 0093, read just before `installs-historical-refused` |
| `framework-pid` | `pidof system_server` | Component trial 4, capture 0003, its fourth line |
| `framework-stat` | `cat /proc/957/stat` | Component trial 4, capture 0003, its fifth line |
| `systemui-pid` | `pidof com.android.systemui` | Component trial 4, capture 0012 |
| `systemui-context` | `cat /proc/1839/attr/current` | Component trial 4, capture 0013, its context up to the closing NUL |

All 50 staged listings, 10 install dumps, 70 package paths, 106 file digests, 11 fingerprints,
82 boot IDs and 70 UID lists in those trials parse with these parsers. The fixtures are a
representative subset. Four of the listings were read just before an install dump in the same
framework instance, and the observer joins those pairs. The trials read the plain listing's
`--only-parent` form. Without children the plain listing prints the same bytes, so the observer
tests serve these captures for the plain command.

### Captured on the D3 guest

The D3 guest run of 2026-10-10 ran the chosen test image on one fresh guest, in its first boot, as
the shell user, with SELinux enforcing. The checkpoint groups lie in one boot and framework
instance, system_server 937 started at tick 10829. The earlier boot wait samples have no such
identity brackets, and qualify only their output form. Each fixture was copied unchanged from
the numbered capture that the table names. Only the device command is kept.

| Fixture | Command | Source |
| --- | --- | --- |
| `shell-identity` | `id` | Capture 0213, the first baseline identity read after the boot wait |
| `checkpoint-helper-digest` | `sha256sum /data/local/tmp/andrix-d3/andrix-checkpoint-read.jar` | Capture 0236, the only digest read, after the helper's only push |
| `checkpoint-read-committed` | `CLASSPATH=/data/local/tmp/andrix-d3/andrix-checkpoint-read.jar app_process /system/bin CheckpointRead` | Capture 0240. Captures 0304 and 0361 are the same bytes. |
| `sm-supports-checkpoint-true` | `sm supports-checkpoint` | Capture 0241. Captures 0305 and 0362 are the same bytes. |
| `boot-id-3e3ad786` | `cat /proc/sys/kernel/random/boot_id` | Capture 0237, just before the first helper reading |
| `uptime-997` | `cat /proc/uptime` | Capture 0218 |
| `framework-pid-937` | `pidof system_server` | Capture 0238 |
| `framework-stat-937`, `framework-stat-937-later` | `cat /proc/937/stat` | Captures 0239 and 0246, just before and just after the first helper reading. Their counters differ, their start time does not. |
| `version-uid-list-systemui-first` | `pm list packages --user 0 --show-versioncode -U com.android.systemui` | Capture 0224. Capture 0355 is the same bytes. |
| `factory-version-list-systemui-first` | `pm list packages --user 0 --factory-only --show-versioncode com.android.systemui` | Capture 0222 |
| `vdc-needs-checkpoint-inaccessible` | `vdc checkpoint needsCheckpoint` | Capture 0229. `vdc checkpoint supportsCheckpoint`, capture 0228, gave the same reply. |
| `boot-completed`, `boot-not-completed` | `getprop sys.boot_completed` | Derived from source before. Captures 0220 and 0050 hold exactly these bytes, with status 0 and nothing on standard error. |

## Source derived forms

These were derived from the pinned framework and vold sources, with illustrative values. The next
section says what the D3 guest showed of them. A form that no guest has shown must be qualified on a
guest before the observer relies on it.

| Fixture | Command | Derivation |
| --- | --- | --- |
| `listing-plain-children` | `pm list staged-sessions` | `PackageManagerShellCommand.printSessionList` and `printSession`. Without `--only-parent`, children of a multiple package parent follow it, one indent deeper, and a child it cannot find prints `not found`. |
| `installs-active-referrer` | `dumpsys -t 25 package installs` | `installs-active-ready` with `referrerUri` set to a ticket nonce. It was rendered again through the writer model, because the value changes the wrapping. |
| `installs-silent-tail` | the same | `installs-historical-refused` with one record of `SilentUpdatePolicy.dump` before the gentle update section |
| `vdc-needs-checkpoint-pending`, `vdc-needs-checkpoint-none` | `vdc checkpoint needsCheckpoint` | Withdrawn. `system/vold/vdc.cpp` answers with exit status 1 or 0 and prints nothing |
| `vdc-needs-checkpoint-failed` | the same | Withdrawn. A failed binder call exits with `ENOTTY`, 25. The error text is illustrative, because only the status is fixed in the source. |
| `vdc-supports-checkpoint` | `vdc checkpoint supportsCheckpoint` | Withdrawn. The same, 1 for supported |
| `checkpoint-read-pending` | the checkpoint helper | `tests/checkpoint-read`: both calls answered, `supports=true` and `needs=true`, status 0 |
| `checkpoint-read-unsupported` | the same | Both answered, `supports=false`. What `needs` answers on such a device is not known; `false` is illustrative. |
| `checkpoint-read-call-failed` | the same | A call threw: its answer is `error:` and the exception's class, status 5. `needsCheckpoint()` enforces MOUNT_FORMAT_FILESYSTEMS, so a caller without it would get a SecurityException. The class is illustrative. |
| `checkpoint-read-service-absent` | the same | No `mount` service: `error=service-absent`, status 3 |
| `checkpoint-read-lookup-failed` | the same | The reflective lookup threw: `error=lookup:` and the class, status 4. The class is illustrative. |
| `checkpoint-read-arguments` | the same | Arguments given: `error=arguments`, status 2. The observer never gives any. |
| `sm-supports-checkpoint-false` | `sm supports-checkpoint` | Taken to print the boolean as the captured `true` does. `cmds/sm` was not inspected for this change. |
| `version-uid-list` | `pm list packages --user 0 --show-versioncode -U com.android.systemui` | `PackageManagerShellCommand.runListPackages` with both options |
| `factory-version-list` | `pm list packages --user 0 --factory-only --show-versioncode com.android.systemui` | The same with `MATCH_FACTORY_ONLY`, which lists the factory copy |
| `installs-destroyed-ready` | `dumpsys -t 25 package installs` | `installs-active-ready` with `mDestroyed=true` and the ready flag kept: a staged session abandoned in this framework instance, which the listing no longer shows |
| `installs-historical-outcomes` | the same | Removed staged sessions of known outcome: an abandon (`-115`, "Session was abandoned"), a refusal with the same status ("User rejected permissions"), and terminal sessions that Android expired after 21 days, applied and failed, which keep their flags (`PackageInstallerService` lines 637 to 648) |
| `installs-historical-unknown` | the same | A removed session that was committed but holds no terminal flag, whose outcome has no known form |
| `installs-foreign-records` | the same | Records of other packages beside the captured finalized SystemUI session: one whose permission map has no known form, a multiple package family with two children (`ParentChildSessionMap.dump`), and a removed family |
| `installs-unknown-package` | the same | A staged session with no package name |
| `uptime` | `cat /proc/uptime` | The kernel's format, seconds since the boot and idle seconds, each with two decimals. The kernel source is not pinned here. |
| `users-two` | `dumpsys user` | `UserManagerService.dump` and `dumpUserLU`, with `UserInfo.toString` and `UserState.stateToString`: the current user, an empty line and `Users:`, then for each user `UserInfo{id:name:flags}` with `serialNo=` and `isPrimary=`, and its own lines indented by four spaces or more, one of them `    State: `. An empty line and `Device properties:` end the section. Here user 0 and a full secondary user 10 with serial 12, both RUNNING_UNLOCKED. The times, fingerprint, restrictions and property lines are illustrative. The parser reads only the section's frame, each user's line, `Type:` and `State:`. |
| `systemui-pids-two` | `pidof com.android.systemui` | This source derived model has one SystemUI process for each of its two users. Which processes actually run needs a guest capture. Toybox's `pidof` prints every match on one line, separated by spaces. The toybox source is not pinned here. `systemui-pid` is the captured form of one process. |
| `systemui-status-1839`, `systemui-status-4721` | `cat /proc/<pid>/status` | The kernel's `task_state`: one `Key:` line each, a tab before the value, and `Uid:` with the real, effective, saved and file system IDs. The kernel source is not pinned here, and the values other than `Pid:` and `Uid:` are illustrative. The UIDs are 10112, the captured app ID, for user 0, and 1010112 for user 10, from Android's range of 100000 UIDs for each user. |
| `systemui-context-4721` | `cat /proc/4721/attr/current` | The captured `systemui-context` with the categories that `levelFrom=user` gives user 10: c522,c768, which is 512 plus the user and 768 plus the user divided by 256. That rule is libselinux's Android code, which is not pinned here. |

## What the D3 guest showed

A separate analysis read the sealed captures again with these parsers. Each command was parsed with
its own parameters. It confirmed the classifications in `forms.json`:

| Fixture | Guest | Evidence |
| --- | --- | --- |
| `uptime` | form | Captures 0218 and 0351 |
| `installs-active-referrer` | form | Capture 0297: exactly the ready session created at capture 0287 carries that create's nonce, in the active section |
| `installs-unknown-package` | form | Captures 0322 and 0323: one unnamed staged session, active, which the observer's join refuses |
| `version-uid-list`, `factory-version-list` | form | Captures 0224, 0355 and 0222. The guest lists SystemUI first and the vendor overlay of SystemUI at versionCode 1, where the fixtures list the overlay first at 37. The parsers read the same SystemUI row from both. |
| `listing-plain-children` | partial | Children one indent deeper (0257) and a SystemUI child (0338). No child that is not found. |
| `installs-historical-outcomes` | partial | The abandon (0274 and 0314). Not the refusal "User rejected permissions", nor the two outcomes that Android expires. |
| `installs-foreign-records` | partial | The live family (0259) and the removed family (0262). Not the record whose permission map has no known form. |

The guest showed none of `installs-silent-tail`, `installs-historical-unknown`, the four source
derived vdc forms, the users and process forms, or the helper's source derived forms. Capture 0312 was taken at
once after an abandon and already shows the session historical, so `installs-destroyed-ready` stays
unshown.

The run's own report differs on four forms. Its parser step compared more than the form:

- **`framework-stat`.** The report marked it different. The step parsed this fixture, read from
  PID 957, against the capture's command for PID 937, so the fixture refused. Capture 0217 itself
  parses with its own PID, and so did every identity bracket of the run.
- **`version-uid-list` and `factory-version-list`.** The report marked them different because the
  listing order and the overlay's version differ from the illustrative fixtures. The form is the
  guest's, and the values are not.
- **`vdc-needs-checkpoint-failed`.** The guest's reply is status 127 from the shell, which cannot
  run vdc at all, not a refusal from vold. No vdc form is qualified.

The report itself stays as sealed.

## The checkpoint route

The shell user cannot run vdc on the test image, so the observer never reads it. The vdc forms
above are kept unqualified, as the record of the withdrawn route. The observer reads the checkpoint
through the framework's storage service instead, with the fixed helper of
[`tests/checkpoint-read`](../../../../../tests/checkpoint-read/README.md). Its README holds the
protocol, the reproducible build and the device contract.

- **Classification.** One reading decides. COMMITTED needs `supports=true` and `needs=false` in
  that reading, and PENDING `supports=true` and `needs=true`.
- **No fact.** A device without support, every refusal, any standard error, and any other form give
  no fact.
- **Admission.** Before the helper runs, `id` must show UID 2000 in the shell's domain, and
  `sha256sum` must give the admitted digest. Both are read again after it, within one boot and one
  framework instance.
- **Companion reads.** `sm supports-checkpoint` reads support only, and never gives a CHECKPOINT
  fact. `vold.checkpoint_committed` is never read.

The guest qualified only the committed answer, after boot completion. The pending answer awaits
D5's activation boot.

## Users, processes and the health probe

`dumpsys user` gives every user or none. The notice rule and the start of each user's health span
rely on that, so a listing cut short, a user line or state of no known form, a repeated user or
serial, or a line outside the section's frame refuses the whole read. The section must also agree
with `Started users state:`, which the same dump prints from the same user states after the
restriction lists: every user named there with its state, and no other user with a state. A
user's name is free text and may hold `} serialNo=`. The greedy name leaves the line's own suffix,
which the dump prints last. States map to the records' USER classifications: RUNNING_UNLOCKED as
itself; BOOTING, RUNNING_LOCKED and RUNNING_UNLOCKING as RUNNING_LOCKED; STOPPING, SHUTDOWN and
`-1`, a user with no state, as NOT_RUNNING. A user marked `<removing>`, and a user and serial read
before that the listing no longer shows, are REMOVED.

The observer accepts SystemUI processes for several users. Which processes run for each user or
profile still needs guest captures. It reads each process's UID from its status and its SELinux
context, and keys it by user, the UID divided by 100000. Two processes for one
user have no known form. The ACTIVE fact takes the system user's process, whose UID must be the
package's. The health probe reads no SystemUI process at all only from pidof's quiet failure, exit
status 1 with no output and no error, and only when a second read in the same bracket gives the
same. Any other failure, such as a refused `/proc` or a lost connection, is an unavailable read,
which gives no fact and never a crash.

The health probe covers three of the plan's criteria for each running unlocked user. Bit 0,
SystemUI's UID and context: exactly that user's process, with the package's app ID and the
expected SELinux domain. The categories are not checked, because their rule is not pinned here.
Bit 4, the active bytes: the active APK's digest is the expected one. Bit 1, no crash or ANR, only
against a baseline from an earlier probe of the same boot and framework instance: the user's
process is still the one the baseline names. A reboot or a framework restart ends every app, so it
starts a new baseline rather than counting as SystemUI's crash. For the system user, a crash, or
an ANR that ends the process, gives CRASH. An ANR that does not end the process is not seen. A miss
of bit 0 or 4 gives DEGRADED, and so does the system user's SystemUI missing, which is observed,
not unavailable.

Only the system user's SystemUI is persistent. In the pinned `ProcessList.newProcessRecordLocked`,
a process is marked persistent, with its adjustment capped at the persistent level, only when its
user is the system user, and `startPersistentApps` starts the persistent apps that
`getPersistentApplications` gives, which are the system user's. Another user's SystemUI is
therefore an ordinary process that Android may end to free memory. Its process ending, or missing,
gives INCONCLUSIVE: the probe cannot tell a crash from such a kill, and an unavailable judgement
never counts as a failure.

A probe without a baseline gives no HELD fact, only the baseline. A HELD fact that leaves out bit 1
would read as partial criteria and leave the whole window INCONCLUSIVE. A miss such a probe sees is
still reported. D5 therefore takes one baseline probe before the window opens, in the
activation boot and the same framework instance, so the window's first probe already covers bit
1.

D5's transport must preserve completion, status and both output streams. A timeout, launch error
or adb failure must never become pidof's quiet exit 1. An unavailable probe must not replace the
last good baseline in the same boot and framework instance. A changed identity ends that baseline.
D5 combines the readers into a complete probe for every criterion its plan declares. Separate
partial HELD facts would leave doubt for the whole window.

## Criteria for D5's vehicle

The UI marker (bit 2) and keyguard unlock with CE authority (bit 3) need the user in the
foreground. Switching users is a lab action, not a read, so the observer's allowlist cannot hold
it. D5's vehicle admits and records each switch, then reads. The read forms it is expected to use,
none of them qualified yet:

- `am get-current-user` before and after each switch.
  `ActivityManagerShellCommand.runGetCurrentUser` prints the user ID on one line.
- `dumpsys user`, as above, for RUNNING_UNLOCKED, which shows that CE storage is unlocked.
- For the keyguard, a window dump that shows whether the keyguard is showing for the foreground
  user. The window manager's shell sources are not pinned here, so its form is open.
- For the UI marker, `uiautomator dump` and the marker's text in the hierarchy, as the
  2026-09-22 trials read the clock. Its form must be captured.

Native work (bit 5) and the recovery route (bit 6) have no reader yet. Until they do, a plan that
declares those bits gets INCONCLUSIVE, never HEALTHY, from these probes.

Guest checks for D5:

- How often another user's SystemUI ends while that user runs in the background, and whether it
  restarts on its own.
- Whether the system user's SystemUI ever restarts without a crash, for example when an overlay
  changes. Such a restart would read as CRASH.
- Whether `dumpsys activity exit-info com.android.systemui` (`AppExitInfoTracker`) tells a crash
  or an ANR from a kill to free memory, for each user. If it does, it can replace process
  continuity for bit 1, and see an ANR that does not end the process.
- Whether the pinned build prints anything between the guest restrictions and the started users in
  `dumpsys user`. The reader admits nothing there, so such a line would refuse every listing.
- Whether a user's name can hold a line break. The reader would refuse every listing then.

## Records of other packages

A record that matches no known form refuses the whole dump when it could concern SystemUI. That
covers a record of SystemUI, a record whose package is unknown, and a multiple package family with
a child of SystemUI or of an unknown package. A record or family certainly about other packages
gives no session and blocks nothing. The fields before `appPackageName` hold no free text, so the
package named there decides "certainly". The derived forms above reach each of these paths.

The D3 guest showed some of these paths on real bytes:

- A live and a removed family of other packages, which block nothing.
- An unnamed staged session, which refuses the join.
- A live family with a SystemUI child and an unnamed child, which refuses the dump (capture 0340).
- That family removed, which refuses it too (capture 0344).

A record whose permission map has no known form still awaits a capture.

## How the forms are pinned

`pm list staged-sessions` and `dumpsys package installs` print through
`android.util.IndentingPrintWriter`, which wraps at 120 columns. A pair that would cross the
limit moves whole to the next line. A pair longer than a line, or one string printed in a single
call, is cut at the limit, possibly inside a word or after a space. The historical section's
parameters are such a string. The listing and dump parsers model that writer, rebuild the
writer's calls from the fields they read, and require the same bytes. The ordered field lists
come from `PackageInstallerSession.dumpLocked`, `PackageInstallerHistoricalSession.dump`,
`PackageInstaller.SessionParams.dump` and `PackageInstallerService.dump`. No value of a known
form holds a space followed by a field name and `=`, so a value that does is refused. Otherwise
an unknown field could hide inside the free text before it, because the writer prints both
alike.

In the pinned source, `SessionParams.dump` prints `referrerUri` with `printPair`, which prints
`String.valueOf` of the `Uri`. `pm install-create --referrer` stores `Uri.parse` of its argument,
whose `toString` returns the argument unchanged, and Package Manager persists the referrer in the
session file. Dumpsys should therefore show the referrer of every session in every section,
unscrubbed. A ticket passes `andrix-ticket:` followed by its 32 hexadecimal digit nonce. The D3
guest showed that form for a ready session in the active section (capture 0297). The reconciler
already binds a qualified matching nonce on the shell route, so that observed form can resolve a
lost create reply. This is an engineering clarification, not new installation authority. Nonce
exclusion as proof of absence remains device only. The shell route still needs a later complete
listing with no staged session for the package when no matching session was observed.
