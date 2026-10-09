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
