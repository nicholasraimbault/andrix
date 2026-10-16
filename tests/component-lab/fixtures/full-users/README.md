# Full user forms

These fixtures hold the shell outputs that the parsers of
[`full_users.py`](../../full_users.py) accept. `forms.json` gives each form's device command, exit
status, standard error, origin and source. Each `<name>.out` holds the standard output byte for
byte. [`test_full_users.py`](../../test_full_users.py) parses every form and derives the contrary
copies from them: a dump cut at every line, repeated users, serials and sections, and dumps that
disagree with themselves or with the user list read around them.

Every form here has the origin `source`: it was derived from the Android source that `source`
names, relative to the `frameworks/base` tree the guest image is built from, with illustrative
values. No guest has shown any of them. A form that a guest prints differently is refused, never
repaired, so the first guest that reads these commands qualifies or refutes each one, and its
retained captures belong beside these files with the origin `captured`.

The simulated guest of [`sim_users.py`](../../sim_users.py) prints exactly these bytes for the
same users, and the suite checks that, so the broker tests read the same forms.

## The forms

| Fixture | Command | What the source fixes |
| --- | --- | --- |
| `dump-system-only`, `dump-created`, `dump-background`, `dump-foreground` | `dumpsys user` | `UserManagerService.dump` with no argument and `dumpUserLU`, through every section to the non-compliance log, whose last subsection is counted. The users in ID order, each with `UserInfo{id:name:flags}`, its serial, type, flags with their names, state, times, the three restriction lists and its user properties; the global and guest restrictions; the started states and cached user IDs; the switchable user capabilities; the visibility mediator's current and visible users; the listener counts; every user type; the system package allowlist. A single service dump has no header or trailer of its own: retained captures of `dumpsys -t 25 package installs` begin and end with the service's own text. |
| `list-system-only`, `list-created`, `list-background` | `pm list users` | The user service's `list`: `Users:` and one tab indented `UserInfo` line for each user that is not partial or precreated, ` running` for a started user. Names are resolved, so the system user is `Owner` here and `null` in the dump. |
| `supports-true` | `pm supports-multiple-users` | One line, `true` or `false`. |
| `max-users`, `max-of-type` | `pm get-max-users`, the same with `--user-type android.os.usertype.full.SECONDARY` | The effective switchable maximum, and the number of users of the type the device allows now: those that exist and those it can still create. |
| `max-running` | `pm get-max-running-users` | The running user limit. |
| `create-success`, `create-refused-maximum`, `create-refused-restriction` | `pm create-user --user-type android.os.usertype.full.SECONDARY AndrixLab` | `Success: created user id <id>`, or the ServiceSpecificException and `Error: couldn't create User.` on standard error with status 1: code 6 for a maximum, 10 for `no_add_user`. |
| `start-success`, `start-failed` | `am start-user -w 13` | Status 0 either way: `Success: user started`, or `Error: could not start user` on standard error. |
| `switch-success`, `switch-failed`, `switch-not-switchable` | `am switch-user -w 13` | Nothing and status 0; `Error: Failed to switch to user 13` with status 1; `Error: UserSwitchabilityResult=<n>` on standard error with status 255. An interrupted wait prints an error and exits 0; the parser takes it as of no known form. |
| `current-user` | `am get-current-user` | The user ID on one line. |
| `visible-true` | `cmd user is-user-visible 13` | `true` or `false`. |
| `setup-null`, `setup-complete` | `settings get --user 13 secure user_setup_complete` | The setting's value, or `null`. |
| `setup-step` | `input keyevent KEYCODE_ENTER` | Nothing and status 0. |
| `install-existing`, `enable` | `pm install-existing --user 13 dev.andrix.lab.notice`, `pm enable --user 13 dev.andrix.lab.notice` | `Package <name> installed for user: <id>`, printed with status 0 whatever the install returned unless the package is missing; `Package <name> new state: <state>`, read back after the change. |
| `uid-list-13` | `pm list packages --user 13 -U com.android.systemui` | Every package whose name holds the filter, in no fixed order, each with its UID for that user. |
| `path-fixture` | `pm path --user 13 dev.andrix.lab.notice` | `package:` and the base APK path; status 1 with nothing printed when the user does not have it. |
| `pidof-two`, `pidof-none` | `pidof com.android.systemui` | One line of PIDs, or status 1 with nothing printed. Toybox's pidof is not pinned here. |
| `cmdline-4734` | `cat /proc/4734/cmdline` | The process name, then NULs: AndroidRuntime clears the argument block before copying the name in. How much of it the kernel shows is not pinned here. |
| `status-4734`, `stat-4734`, `context-4734`, `status-denied` | `cat /proc/4734/status`, `.../stat`, `.../attr/current` | The kernel's forms, not pinned here: `Name`, `Pid` and the four `Uid` fields; the task name, the last 15 characters of the dotted process name that Zygote sets, and the start time in clock ticks, field 22; the context ended by one NUL. A refusal is status 1 with the error on standard error. The context's categories follow the `levelFrom=user` rule of the existing readback fixtures, 512 plus the user; that rule is libselinux's and is not judged. |

## Values that are illustrative

The users' times, fingerprint, user properties, listener objects, the user types' details and the
package allowlist are illustrative. So are the numbers: user 13 with serial 41, the system user's
SystemUI UID 10112 from the retained captures, the processes' PIDs and start ticks, the switchable
maximum 4 against a built-in 32, and the running limit 3. The guest decides each of them. Their
forms are the source's: a user type's `mEnabled`, for one, is the boolean the dump prints as `true`
or `false` (`UserTypeDetails.java:55, 414`), never its builder's configured integer. Whether the
selected image prints a built-in maximum, a creation override line or anything else in these
sections is a guest question; a line the parser does not expect refuses the whole dump.
