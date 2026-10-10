# Shell readback forms

These fixtures hold the shell outputs that the exact readback parsers in
`scripts/proof/systemui_sessions.py` accept. `forms.json` gives each form's device command, exit
status, standard error and origin. Each `<name>.out` holds the standard output byte for byte.
`scripts/proof/tests/test_systemui_readbacks.py` parses every form and derives the failing controls
from them: a truncated form, a reordered section or field, an extra field and an unexpected value.

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

## Source derived forms

No guest capture exists for these. They were derived from the pinned framework and vold sources,
and must be qualified on a guest before the observer relies on them.

| Fixture | Command | Derivation |
| --- | --- | --- |
| `listing-plain-children` | `pm list staged-sessions` | `PackageManagerShellCommand.printSessionList` and `printSession`. Without `--only-parent`, children of a multiple package parent follow it, one indent deeper, and a child it cannot find prints `not found`. |
| `installs-active-referrer` | `dumpsys -t 25 package installs` | `installs-active-ready` with `referrerUri` set to a ticket nonce. It was rendered again through the writer model, because the value changes the wrapping. |
| `installs-silent-tail` | the same | `installs-historical-refused` with one record of `SilentUpdatePolicy.dump` before the gentle update section |
| `vdc-needs-checkpoint-pending`, `vdc-needs-checkpoint-none` | `vdc checkpoint needsCheckpoint` | `system/vold/vdc.cpp` answers with exit status 1 or 0 and prints nothing |
| `vdc-needs-checkpoint-failed` | the same | A failed binder call exits with `ENOTTY`, 25. The error text is illustrative, because only the status is fixed in the source. |
| `vdc-supports-checkpoint` | `vdc checkpoint supportsCheckpoint` | The same, 1 for supported |
| `version-uid-list` | `pm list packages --user 0 --show-versioncode -U com.android.systemui` | `PackageManagerShellCommand.runListPackages` with both options |
| `factory-version-list` | `pm list packages --user 0 --factory-only --show-versioncode com.android.systemui` | The same with `MATCH_FACTORY_ONLY`, which lists the factory copy |
| `boot-completed`, `boot-not-completed` | `getprop sys.boot_completed` | `1` once the boot completed, an empty line before. The trials' reads of it failed during the boot and give no form. |
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
package named there decides "certainly". The derived forms above reach each of these paths. All
of them await guest captures.

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

The referrer finding is pending a guest capture of a session with a referrer. In the pinned
source, `SessionParams.dump` prints `referrerUri` with `printPair`, which prints `String.valueOf`
of the `Uri`. `pm install-create --referrer` stores `Uri.parse` of its argument, whose `toString`
returns the argument unchanged, and Package Manager persists the referrer in the session file.
Dumpsys should therefore show the referrer of every session in every section, unscrubbed. A
ticket passes `andrix-ticket:` followed by its 32 hexadecimal digit nonce.
