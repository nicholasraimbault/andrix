# Output expectations and evidence boundaries

These references name the pinned Android source, not an upstream branch with similar names.
Line numbers are for the supplied base. A source supported expectation is not a guest result.
Every Android command form and runtime outcome below still needs guest calibration. Malformed,
missing or unexpected selected state is refused, never repaired. The raw transport, image,
process and file capture provenance remains the admitted vehicle's responsibility.

Abbreviations, relative to the Android source root:

- F: `frameworks/base`.
- PM: `F/services/core/java/com/android/server/pm`.
- P: `F/services/permission/java/com/android/server/permission/access`.
- N: `F/services/core/java/com/android/server/notification`.
- J: `F/apex/jobscheduler/service/java/com/android/server/job`.
- C: `F/core/java/android`.

## Android tool observations

### Instrumentation

`am instrument -w -r` finishes by printing sorted result keys as
`INSTRUMENTATION_RESULT: key=value` and one `INSTRUMENTATION_CODE: code` line.
Source: `F/cmds/am/src/com/android/commands/am/Instrument.java:190-208`.
The subject supplies exactly one result key. Its JSON and signature schema are defined by
`ObserveState.PAYLOAD_FIELDS` and `protocol.PAYLOAD_FIELDS`, with host equality tests.

`--no-test-api-access` and `--always-check-signature` are parsed in
`F/cmds/am/src/com/android/commands/am/Am.java:163-195`. Instrumentation is not a zero write
promise. Ordinary instrumentation can kill/relaunch the target and report system interaction,
`F/services/core/java/com/android/server/am/ActivityManagerService.java:15553-15569`. Finish can
change OP_NO_ISOLATED_STORAGE, `15844-15851`. These are unselected bookkeeping effects. The
fixture never calls UiAutomation or adopts permissions. Bookend selected Android states anyway.

Guest gate: actual self instrumentation admission, strict envelope, correct UID/serial/signer,
AndroidKeyStore generation/use, CE/DE access, no selected state change from observing, and both
signatures surviving the entire staged lineage. A disposable SDK build confirms none of these.

Keystore public API limitation: under `F/keystore/java/android/security/keystore2/`,
`AndroidKeyStoreSpi.java:164-178,1158-1163` converts metadata errors to a false containsAlias.
Its listing also converts errors to an empty batch, `1138-1148,1352-1383`. The fixture therefore
additionally calls getKey for both fixed aliases before any write and immediately before each
generation, without catching errors. Spi `123-140` and
`AndroidKeyStoreProvider.java:431-455` propagate failures for private keys and return null for
KEY_NOT_FOUND or a pure certificate entry. Selected existing private keys cannot be overwritten
because of an unavailable service. The public API still cannot prove an entirely empty arbitrary
namespace when certificate metadata or enumeration errors are swallowed. Fresh independent
package/UID provenance and complete provider diagnostics are necessary. Every partial setup
created by this fixture is independently blocked by its fixed DE intent. Arbitrary namespace
preconditions during provider fault injection remain unqualified, not a tested refusal claim.

### Package Manager and native diagnostic

List rendering, including UID suffix:
`PM/PackageManagerShellCommand.java:976,1162-1179`.
Code path rendering and successful/failed result:
`PM/PackageManagerShellCommand.java:741-756`.
Selected setting dump fields:
`PM/Settings.java:5344-5363,5380-5385,5713-5725`.
Scanned package object text:
`F/core/java/com/android/internal/pm/parsing/pkg/PackageImpl.java:880-883`.
The complete package/shared maps reuse `tests/native-identity/uid_observe.py` in the repository.

The mapped deferred surface, including empty admitted list, exit 1 from pm path, pkg=null and
original installed setting, is a prediction from PM lookup and retained settings, not a fresh
B2 result. Package UID lookup distinguishes scanned and known/uninstalled settings at
`PM/ComputerEngine.java:2757-2788`; the full settings map is returned at `3633-3635`.
The new APK hash and instrumented contract need new artifact admission.

The exact diagnostic command is `dumpsys -t 30 package --andrix-native-identities`: like every dump
this subject is read through, it runs with an explicit 30 second dumpsys bound in place of dumpsys's
default 10 seconds (`protocol.dumpsys_argv`). dumpsys exits 0 after almost every outcome
(`frameworks/native/cmds/dumpsys/dumpsys.cpp`, GrapheneOS `2026081300`, line 313): a dump that outlives
the bound is cut and followed by `*** SERVICE 'S' DUMP TIMEOUT (Nms) EXPIRED ***` (lines 299-302,
558-562), and a service error, a missing service or a failed transfer is a line on stderr after
whatever was written (lines 418-422, 434, 440, 528, 540, 550). So every capture passes one
completeness gate before anything reads it (`uid_observe.complete_capture`, through
`observations.capture_text` and `b2_dump_assess.assess_phase_capture`): its transport completed,
dumpsys exited 0, its stdout carries no timeout line and ends with a line feed, and its stderr is
empty. Any other capture is unavailable with its own reason, never a shorter complete dump; the
parsers themselves still refuse the timeout line. Its route is in
`patches/grapheneos-2026081300/native-principal-pins.patch:744` in the repository. Schema choice,
scalars, holds, slot rows and deferred names are rendered by
`owner/tests/platform/native_recovery_fragments/diagnostic-dump.java.inc:8-74`.
The strict parser is reused from `tests/native-identity/observe.py:156-289`. Require schema 3
for B2 and schema 2 for B1, never either opportunistically. Expected layout facts still belong
to the particular staged input and both pinned readers, not just this subject parser.

Guest gate: original full mapping, shared map exclusion, image specific schema, exact retained
setting, code identity, deferral, later admission and unchanged native input. A failed launch
alone proves none of them. Compiled ART cache deletion is not selected APK/data deletion.

### Permission manager

Both `--app-id` and `--package` dump the saved state:
`P/permission/PermissionService.kt:2191-2225`.
The App ID, User, Permissions, UID App ops, Package, version and package App ops nesting is at
`P/permission/PermissionService.kt:2306-2366`. Other ordinary permission/operation rows are
recorded, not used as substitutes. The dedicated app must have only user 0 and this package.

Internal RUNTIME_GRANTED is 16 and USER_SET is 32:
`P/permission/PermissionFlags.kt:90,100`.
Flag formatting is at `P/permission/PermissionFlags.kt:545-571`.
The selected row must be granted=true and exactly `[RUNTIME_GRANTED|USER_SET]`, not API flags.
Migration version comes from saved package state and must be pinned from baseline. It is not
APK versionCode and is not guessed from a feature flag.

Grant and flag shell routes:
`PM/PackageManagerShellCommand.java:2707-2786,2820-2861`, with user-set registered at line 180.
These are setup effects only. Runtime effective checks in the subject are secondary and only
performed after ordinary admission. They cannot substitute for saved flags while deferred.

Guest gate: initial denied/zero baseline, exact final grant/flags, migration version and saved
state retention at every boot. An unexpected initial flag stops setup rather than being cleared.

### App operation

Package get also includes any UID override, while numeric UID get queries only UID modes:
`F/services/core/java/com/android/server/appop/AppOpsService.java:6080-6125`.
Default output and timestamp rendering continue at `6173-6176` and `6116-6172`.
Mode names are `C/app/AppOpsManager.java:502-508,3924-3928`.
Package resolution uses the retained setting route at
`F/services/core/java/com/android/server/appop/AppOpsService.java:5986-5996`.

With no vibrator calls the selected package result is exactly `VIBRATE: ignore\n`; the UID
result is `No operations.\nDefault mode: allow\n`. No `Uid mode:` row or timing suffix is
silently ignored. Unexpected timing text needs assessment and an explicit grammar revision.
Package VIBRATE is distinct from the POST_NOTIFICATIONS permission. Raw operation preflight
uses the public string `android:vibrate`; SDK 36 does not export OPSTR_VIBRATE.

Guest gate: those exact forms, no UID override or access history, and preservation of the
package mode while mapped but deferred and through both image switches.

### Notification channel

The preferences section and package UID rendering are in
`N/PreferencesHelper.java:2305-2316,2330-2392`. The next section is printed by
`N/NotificationManagerService.java:8780-8784`. The package filter is a string filter, so the
parser still requires the exact package and numeric UID, including no restored-without-UID row.

The complete channel field order and types come from
`C/app/NotificationChannel.java:1704-1752`. User lock is hex without 0x in that dump, so 100
means 256. `USER_LOCKED_ALLOW_BUBBLE` and initial allow bubbles constants are at `252,271-279`.
The built in channel command cannot establish this lock. It stores NMS's local binder stub,
`N/NotificationShellCmd.java:123-130`, fetches the stored object itself through
`N/NotificationManagerService.java:5454-5474` and `N/PreferencesHelper.java:1508-1522`, then changes
that alias before update, `N/NotificationShellCmd.java:317-322`. The comparison sees no change,
so its 1/0 result is refused. Creation resets app supplied bubbles and locks at
`N/PreferencesHelper.java:1192-1203`; an app update is not a substitute either.

The selected route is the separate ordinary shell command traced in [SETUP.md](SETUP.md), with
candidates and complete source references. It requires UID 2000, rejects a local interface and
uses the existing remote methods in C/app/INotificationManager.aidl:110,113. It additionally
makes an explicit independent Parcel copy before changing any field, using
`C/app/NotificationChannel.java:350-396,428-483,1630-1635`. NMS accepts shell at
`N/NotificationManagerService.java:5607-5611,13473-13482` and forwards a user update at `3977-3981`.
PreferencesHelper compares separate old/new channels at `1283-1304` and the changed bubble field
locks bit 256 at `2300-2301`, then replaces the stored object at `1314`. NMS queues persistence
at `4007,1451-1454`. This does not depend on a mutation of the stored alias.

The separate setup jar hash is pinned before and after issue. Its acknowledged return is
stage=update_returned with state_proven=false, not preference or durability proof. Both owner
parsers still default to stage='retained' and require 1/256. Explicit 'created' means the -1/0
precondition only, and 'absent' means no initial channel. A reset cannot qualify preservation.

Explicit default audio attributes use `C/app/Notification.java:544-547`. Their print form is
`F/media/java/android/media/AudioAttributes.java:1528-1536`; usage/content constants are at
`154,114`. Default muted haptic channels set internal bit 0x800 at `832,910-913`; its flag name
and trailing space rendering are at `1554,1562-1579`. XML uses public flags only, `679`, hence
flags="0" on disk but 0x800 in the dump. XML read always reconstructs audio attributes,
`C/app/NotificationChannel.java:1289-1297,1529-1538`. Setting a null AudioAttributes object would
therefore create an avoidable before/after difference. No sound URI is selected.

Guest gate: shell entry and non SDK interface access without any exemption, actual Binder and
SELinux admission, full row, initial -1/0 and copied user update 1/256, saved UID, stable remaining
baseline fields, no custom/deleted initial channel, settled persistence and no loss on any boot.
The host object model exercises the command's actual source and clone guard, not Android IPC,
Parcelable, NMS or persistence. The real SDK build checks the separate jar, not runtime admission.

### JobScheduler

Unfiltered registered job headers, complete count and Ready booleans:
`J/JobSchedulerService.java:6437-6492`.
Default namespace '#' identity: `J/controllers/JobStatus.java:1404-1413`.
Ephemeral object hash and component: `J/controllers/JobStatus.java:3151-3156`.
UID form u0a followed by app ID minus 10000: `C/os/UserHandle.java:558-579`.
Source, JobInfo, constraints, timing and conditional run counters:
`J/controllers/JobStatus.java:3351-3647`.
Constraint names/masks: `J/controllers/JobStatus.java:145-159,3173-3226`.
Default priority text: `F/apex/jobscheduler/framework/java/android/app/job/JobInfo.java:2561-2579`.
Duration text, including mandatory lower units: `C/util/TimeUtils.java:250-318`.

Parcelled extras deliberately print just a byte count until unparcelled,
`C/os/PersistableBundle.java:428-436`. Such a line cannot prove markers. Dump constraints and
standby/restriction fields are parsed or recorded, not compared as identity bytes.

A waiting job can also be mentioned by controllers,
`J/controllers/TimeController.java:448-483`. Such references are not execution. Pending queue,
active jobs and recent completion have distinct sections,
`J/JobSchedulerService.java:6615-6679`, `J/JobConcurrencyManager.java:2168-2217`.
Job execution history rendering is `J/JobPackageTracker.java:582-631`. The selected job must
have no queue/execution/history reference, work items or run counters, and no callback sentinel.

Shell lookup first resolves a scanned package with flags 0,
`J/JobSchedulerService.java:6151-6175`. Waiting/ready/component rendering continues at `6178-6236`.
Error text is on stderr, `J/JobSchedulerShellCommand.java:131-155`; error constants -1000 and
-1001 are at `35-37`. A deferred unknown package result is compatible with a retained job.
The transport must report its actual nonzero encoding of the service error.

Own pending JobInfo reads use the Binder caller UID and do not schedule:
`J/JobSchedulerService.java:5471-5513`. The all namespace map preserves its null default key.

Guest gate: exactly one own default namespace job, no filtered/truncated count, correct source,
persistence, timing and component, no execution, exact typed markers on disk and after admission,
UTC rebasing within the chosen tolerance, and no replacement scheduling since setup.

## Persistent copies

`stored.py` consumes decoded XML, not ABX. This is an explicit boundary, not an undocumented
fallback. The binary decoder sources are not under the allowed Android source roots of this
implementation task. An existing offline permission reader is documented at
`tests/permission-store/README.md`; it extracts POST_NOTIFICATIONS flags only. Its decoder must
be separately admitted with its pinned sources before use. No new raw ABX decoder was qualified
here. The platform conversion entry is `F/cmds/abx/src/com/android/commands/abx/Abx.java:75-101`.
Do not use its in place mode or write a service file to make parsing succeed.

- Access user path and asynchronous writes:
  `P/AccessPersistence.kt:107-133,162-186`, `P/util/PermissionApex.kt:23-35`.
  Selected flags serialization:
  `P/permission/AppIdPermissionPersistence.kt:149-191,194-230`.
  Package version writer: `P/AccessPolicy.kt:412-435`.
  UID and package modes:
  `P/appop/AppIdAppOpPersistence.kt:45-98`, `P/appop/PackageAppOpPersistence.kt:45-98`,
  `P/appop/BaseAppOpPersistence.kt:38-68`.
  Require flags 48, package mode 1 and absent UID VIBRATE. Reserve and AtomicFile siblings are
  not optional evidence, see `P/util/AtomicFileExtensions.kt:29-68`.
- Notification policy root and ranking writer:
  `N/NotificationManagerService.java:831,1511-1527`,
  `N/PreferencesHelper.java:262,714-840`. Root version is 1, ranking version is 4.
  Channel attribute defaults and decimal XML integers:
  `C/app/NotificationChannel.java:1282-1335,1374-1479`. Missing sound is no sound, not loss.
  Show badge true, allow_bubbles 1 and locked 256 are required. Decimal 100 is not the dump mask.
- Job primary files and root:
  `J/JobStore.java:110-112,712,750-764,808-832`. Actual split or legacy names must be captured.
  Job attributes, constraints, UTC one off delay, extras and optional work/debug data:
  `J/JobStore.java:865-1014,1018-1084`. Namespace must be absent, source user 0, run times zero,
  no deadline/work and exactly the two typed string markers. PersistableBundle delegates its
  XML map writer at `C/os/PersistableBundle.java:297-312`. The typed map serialization
  implementation is outside the supplied Android roots; its exact string node form remains
  a decoder and guest calibration gate, not independently audited codec evidence here.

Guest/vehicle gate: actual capture forms, strict converter behavior, settled rounds, durable
setup reboot and selected row preservation. A parsed copy alone proves neither durability nor
the next boot's file selection. Unstable captures are unavailable. Never force service
read/write or publish XML.

### Owner roles, captures and agreement

`owner_stores.py` applies each owner's own role rule to a complete captured namespace. The
sources define these rules:

- AtomicFile: `F/core/java/android/util/AtomicFile.java:84-90` names `.new` and `.bak`. A write
  renames a legacy `.bak` back over the base, writes `.new` and renames it over the base,
  `143-162,170-186`; a failed write deletes `.new`, `193-208`. A read renames a `.bak` over the
  base and deletes a `.new` beside a base, `241-259`, so a `.new` alone is never read.
- Access store: `P/AccessPersistence.kt:77-100,166-183` reads and writes the user's `access.abx`
  through `P/util/AtomicFileExtensions.kt:29-70`. A main that fails to parse falls back to
  `.reservecopy` through its own AtomicFile; an absent main does not, and is migrated instead.
  A finished write deletes the reserve and copies the main into it byte for byte, so a settled
  pair is byte equal. The user 0 directory comes from `P/util/PermissionApex.kt:31-32`,
  `F/core/java/android/content/ApexEnvironment.java:79-83` and
  `F/core/java/android/os/Environment.java:565-567`.
- ResilientAtomicFile: a write moves the main to the temporary backup and deletes the reserve,
  `PM/ResilientAtomicFile.java:84-122`, then finishes the main, deletes the backup and copies the
  main into the reserve, `124-167`. A read takes the backup, then the main, then the reserve,
  `185-231`, and removes the main beside a backup. With neither main nor reserve it returns no
  stream, `212-230`, and Package Manager starts without settings, `PM/Settings.java:3586-3595`.
  So an empty family is refused rather than settled. Package settings and user restrictions use
  it, with mode 0660, at `PM/Settings.java:760-768,1693-1709`.
- Notification policy: `N/NotificationManagerService.java:3406,3435-3436` builds its AtomicFile,
  `1422-1447` reads it, `1451-1454` queues a save and `1465-1508` writes it.
- JobStore: `J/JobStore.java:110-112,202-206` names its directory and files. A read lists the
  directory, skips every name but `jobs.xml` and the split pattern, reads each through AtomicFile
  and keeps the first of two equal identities, `1139-1243`. A write can leave `.new` after a
  failure, `808-859`, and migration between split and legacy files runs at `537-545,786-806`.
  Split files are the default at `J/JobSchedulerService.java:843,1073`.

The Access grammar holds at every stage. Its root sections are read at
`P/AccessPolicy.kt:342-410`; the owners and rows at
`P/permission/AppIdPermissionPersistence.kt:149-192`,
`P/permission/DevicePermissionPersistence.kt:44-109`, `P/appop/BaseAppOpPersistence.kt:41-54`,
`P/appop/AppIdAppOpPersistence.kt:37-72`, `P/appop/PackageAppOpPersistence.kt:38-68` and
`P/appfunction/AppIdAppFunctionAccessPersistence.kt:37-117`. Each ignores an unknown element
with a warning, and a repeated owner or row replaces the earlier one, so the reader refuses both.

Binary XML starts with the pinned serializer's magic `ABX` and a zero byte, as the offline
permission store reader records in `tests/permission-store/PermissionStoreChecks.java:51-55`.
Such a file needs the booted image's `abx2xml FILE -` output, which writes to stdout,
`F/cmds/abx/src/com/android/commands/abx/Abx.java:40-62,64-106`. Text XML takes no converter.

The disk record and the dump agree on these values:

- Permission flags render in ascending bit order, an unnamed bit in hexadecimal,
  `P/permission/PermissionFlags.kt:56-313,539-571` and `P/util/IntExtensions.kt:25-38`. The
  rendered grant follows `PermissionFlags.kt:350-370`. Both selectors render one saved state,
  `P/permission/PermissionService.kt:2191-2226,2306-2372`.
- Mode names are `C/app/AppOpsManager.java:502-508,3924-3929`. The package query prints UID
  operations before package operations, with optional access history, and the numeric UID
  query prints UID operations only, `F/services/core/java/com/android/server/appop/`
  `AppOpsService.java:6080-6176`.
- Channel XML omits default values, and its reader restores them,
  `C/app/NotificationChannel.java:280-288,1276-1337,1374-1480`. A preference restored without a
  UID is stored with uid -1, `N/PreferencesHelper.java:741-746,806-813` and
  `C/os/Process.java:73`. The dump also prints rows that hold only the notification permission,
  `N/PreferencesHelper.java:2401-2421`, so UIDs compare among rows that hold channels.
- The dump's earliest run time is relative to the elapsed clock,
  `J/controllers/JobStatus.java:3112-3118,3637-3643`. The stored delay is UTC and is recomputed
  from the wall clock whenever the job is written, `J/JobStore.java:979-1001`, and converted back
  on restore, `1096-1106,1416-1418`. Due times therefore agree within 60 seconds. Run counters
  print at `J/controllers/JobStatus.java:3644-3662`.

Some rendered fields change at a designed phase without any stored change, so later
observations compare without them and each phase checks them on its own:

- Component usability prints apart from the job, `J/JobSchedulerService.java:6476-6492`, and a
  job is kept while its service is unresolved, `J/controllers/ComponentController.java:150-190`.
- Extras print parcelled until unparcelled, `C/os/PersistableBundle.java:428-437`. JobStore's
  write reads their keys, `J/JobStore.java:897-919`, which unparcels them,
  `C/os/BaseBundle.java:819-822`.
- The importance and user set suffix of an AppSettings row comes from the notification
  permission values, `N/PreferencesHelper.java:2352-2361`, which list installed packages,
  `N/PermissionHelper.java:114-181`, and those are the scanned ones only,
  `PM/ComputerEngine.java:1720-1790`. A deferred package's row prints without it.

Guest gates: the Toybox `find`, `stat`, `sha256sum` and `date +%s` output forms, the adb pull
transport and the converter's codec are outside these roots and need calibration on the guest.

## Dummy file tools and APK tools

Actual CE/DE data paths are derived from Context.getDataDir, not getFilesDir, which can create
directories. Source: `C/app/ContextImpl.java:913-918,3721-3740` and
`C/os/Environment.java:616-630,658-672`. The fixture uses nofollow leaf opens and checks the
controlled directory chain, regular type, owner, link count, exact length and exact bytes.

Root observations use sha256sum, stat with explicit `%n|%f|%u|%g|%h|%s` format, and `ls -Zd`.
Their Toybox implementations are outside the allowed source roots and were not inspected.
These are chosen strict format contracts, not source verified guest outputs. They require
calibration. An initial independent metadata/label baseline must be pinned, not a guessed label
or uid supplied by the subject. Read only the dummy files, never keystore secrets.

Producer outputs rest on the actual pinned javac, D8, aapt2, zipalign and apksigner binaries,
whose hashes are in tools.json. Compilation, badging, full manifest dump, alignment and signature
verification are observable host evidence. Tool implementation source is not claimed to have
been audited. aapt2's observed namespace URI format and apksigner's SDK 37 v3 selection are
checked exactly. SDK 36 stubs with manifest SDK 37 remain an explicit build method limit.

None of these observations proves data retention for lost mappings, other Android users,
external data, real note storage, live suspension/lift writers, OTA/locked phone rollback,
KeyMint compatibility, release, deletion or native execution. Those claims remain outside this
fixture. A preservation failure must stop and be attributed, not trigger setup replay or repair.
