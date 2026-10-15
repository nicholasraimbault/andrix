# Full screen notice fixture

The fallback notice route of the [component
transaction](../../plans/2026-10-09-component-transaction.md) for the lab: when SystemUI cannot
deliver decision 7's notice, Andrix's own app shows a full screen notice to each running user and
records a receipt. This directory holds that app as a disposable test fixture, its fixed shell
presentation helper, the host route and reader that the lab broker calls, a standalone producer and
the host tests.

It is not a product route and not part of any image. There is no Soong module and no
`PRODUCT_PACKAGES` entry. The APK is an ordinary test APK with a disposable ordinary signer: no
platform signer, no shared UID, no requested permission, no process attribute and no native account
designation. It proves no SystemUI notice and no real SystemUI failure. Host tests here qualify no
Android form or behavior; see "What only a guest can show".

## Files

| File | Contents |
| --- | --- |
| `AndroidManifest.xml`, `res/` | The APK contract: an activity and a provider, both behind DUMP |
| `src/.../NoticeActivity.java` | The full screen notice and its delivery callbacks |
| `src/.../ReceiptProvider.java` | The read only provider of this user's receipt store |
| `src/.../ReceiptStore.java` | The store: one writer, immutable rows, the whole listing |
| `src/.../Disk.java`, `AndroidDisk.java` | The store's file operations, through android.system.Os |
| `src/.../Writer.java` | The process's one store and its one writer thread |
| `src/.../NoticeRequest.java` | The request: the helper's arguments and the typed extras |
| `src/.../ReceiptRow.java`, `Forms.java` | The row codec and the shared value grammars |
| `src/.../Delivery.java` | The activity's identity and callback decisions, plain Java |
| `src/.../ProviderPolicy.java` | The provider's caller and query decisions, plain Java |
| `present-src/.../NoticePresent.java` | The fixed shell presentation helper, never in the APK |
| `notice_route.py` | The broker's notice adapter: presentation and visibility |
| `notice_reader.py` | The receipt reader: row codec and provider listing |
| `produce.py` | The standalone producer and the artifact checks |
| `tools.json`, `framework-api.json` | The pinned tools and framework sources |
| `pins.json` | The reproducible output pins and the pinned Binder signature |
| `goldens/` | Java's request, row and listing bytes, and the aapt2 manifest dump |
| `javatests*/` | The Java host suites and the model's stubs |
| `test_*.py` | The Python host suites |

## The app

Package `dev.andrix.lab.notice`, versionCode 1, minimum and target SDK 37, compiled against the
public SDK 36. `testOnly`, not debuggable, no backup, no cleartext traffic.

The fixture is signed with its own dedicated key, never the platform key. An app signed with the
platform key would see its launcher's UID without identity sharing
(`ActivityClientController.java` 853 to 865), which would empty the shell check below. The
vehicle's admission checks the installed fixture's signer against the fixture's own certificate and
refuses the platform certificate.

`NoticeActivity` is exported only to holders of DUMP, direct boot aware, shown when locked and
turning the screen on through its manifest attributes. Nothing in the app dismisses or disables the
keyguard: the producer refuses a DEX that names `requestDismissKeyguard`, the insecure dismissal
option or keyguard locks. It asks for no consent and no acknowledgement, has no button, and closing
it changes nothing: a notice never vetoes a reboot.

It refuses, finishing at once with nothing shown and nothing written, unless:

- the intent is exactly the explicit fixture component with the action
  `dev.andrix.lab.notice.action.PRESENT`, no data, type or category, and exactly the typed extras of
  one request (`NoticeRequest`);
- `Activity.getLaunchedFromUid()` is 2000, the shell user. Android reveals the launcher's UID to an
  ordinary app only when the launcher shared its identity (`core/java/android/app/Activity.java`
  7381 to 7418; `ActivityClientController.java` 774 to 803 and 875 to 891). A Binder calling UID in
  an activity callback is not that proof, and plain `am start -W` shares no identity
  (`ActivityManagerShellCommand.java` 842 to 902);
- the user of the app's own process UID and the serial that `UserManager.getSerialNumberForUser`
  gives for `Process.myUserHandle()` are the request's expected user and serial. The request's
  values are a check, never the identity;
- the request's immutable key holds nothing yet, or a row of exactly this request: the honest
  repeat. A key that holds a conflicting row, bytes that are no row of that key, or that cannot be
  read refuses the request, so a conflicting notice is never shown. This check reads only.

Before it sets any content, the activity sends its one decision to the helper's report binder when
the intent carries one: `presented`, or `refused:` and the reason (`request`, `launcher`, `uid`,
`user`, `serial`, `conflict`, `corrupt` or `store`). The binder is a one way callback beside the
request, not part of it. A decision says what the app did with the request, never that a user saw
it.

It shows the title, the unpredictable challenge, the exact notice text, the interruption, the
component, the plan, ticket and entry (or the control action of a qualification) and the text's
SHA-256. The challenge view has the resource ID `dev.andrix.lab.notice:id/challenge`.

The candidate delivery is the first frame commit the app sees while its window has focus, after it
resumed (`ViewTreeObserver.registerFrameCommitCallback`). A committed frame may not yet be visible
(`ViewTreeObserver.java` 760 to 767), so the candidate time is unqualified metadata. The activity
hands that one candidate row to the store's writer; no focus or no committed frame gives no row.

## Rows and the store

A row, `andrix-notice-receipt-v1`, is the magic line and one `name=value` line for each field in a
fixed order, ASCII, each ending in a line feed, at most 2048 bytes: purpose (`TICKET_NOTICE` or
`QUALIFICATION`), installation, component, plan, ticket and index of a ticket's notice or the
control action of a qualification (an absent field is `-`), the host's boot token, the text SHA-256,
the event (the challenge), the app's UID, user and serial, its process ID and start elapsed time,
its resume and first focus times, the candidate rule `focus-then-frame-commit` and the candidate
time. Decimals are canonical, identifiers lowercase hexadecimal, and times ordered: process start,
resume, focus, candidate. An ordinary app cannot read the kernel boot ID; the host binds the boot
token with its unchanged boot brackets.

The immutable key, also the file name, is the purpose, installation, boot token, ticket and index or
control, user and serial, ending in `.row`. The store is `receipts` in the app's device encrypted
data directory. One process per user and one writer thread serialize every write:

1. Before its first row, a process creates the directory if absent and syncs its parent, also when
   the directory exists. An earlier process may have made it and died before that sync, and a
   process restart, unlike a crash, keeps the name visible without making it durable.
2. If the key exists, read and parse the whole first row. The same request is a repeat, which keeps
   the first row and its time; anything else is a conflict or a corrupt row. Nothing is written.
   A repeat syncs the directory before it is accepted, unless this process already made that name
   durable, since an earlier process may have renamed the row and died before its own sync.
3. Otherwise create an exclusive temporary `.<key>.<nonce>.tmp` without following links, write the
   row, sync it through its writing descriptor, close it, rename it to the key, and sync the
   directory.

Only after these syncs is a row WRITTEN or a REPEAT. A failed write, sync or read latches the writer
for the process. Nothing deletes a file: an interrupted temporary stays as a partial write. Opening
the store creates nothing.

## The provider

`ReceiptProvider`, authority `dev.andrix.lab.notice.receipts`, exported only to holders of DUMP and
direct boot aware. Every entry point first checks that `Binder.getCallingUid()` is 2000, before it
reads an argument, and nothing clears the calling identity. The explicit check matters:
`ContentProvider`'s transport calls `query` to learn the columns even for a caller whose read
permission failed (`ContentProvider.java` 266 to 300). The one admitted operation is the whole
listing, `content://dev.andrix.lab.notice.receipts/rows` with no projection or exactly `line`, and
no selection, sort or other argument. Insert, update, delete, batches, calls, every file open, type
queries and URI transforms are refused.

The listing is one `line` column, with lines of these forms:

```
andrix-notice-store-v1 user=U serial=S uid=N status=X
row NAME SIZE SHA256 HEX
partial NAME SIZE SHA256 HEX
corrupt NAME SIZE SHA256 HEX REASON
end rows=R corrupt=C partial=P listing=SHA256
```

The status X is OK, ABSENT (no row was ever written in this user), UNREADABLE or OVERFLOW (more than
64 entries); only OK lists entries. The entries follow in name order. A partial entry is a writer's
temporary. A corrupt entry does not parse, is not its own key, is not this app's identity, is not a
regular file (its bytes are `- - -`), is too large or has an unknown name, listed as `unknown:` and
its bytes in hexadecimal. The end line counts the entries and digests every line before it. The
shell reads the listing with:

```sh
content query --uri content://dev.andrix.lab.notice.receipts/rows --user <id>
```

which prints `Row: N line=TEXT` for each line (`cmds/content/.../Content.java` 649 to 710). It exits
0 even when the provider throws, with an error on standard error, and prints `No result found.` for
an empty cursor. The reader treats the first as unavailable and the second as of no known form,
never as an empty store.

## The helper and the route

`NoticePresent`, run as the shell user:

```sh
CLASSPATH=/data/local/tmp/andrix-notice/andrix-notice-present.jar app_process /system/bin \
  dev.andrix.lab.notice.NoticePresent 1 <user> <serial> <purpose> <installation> <component> \
  <plan> <ticket> <index> <control> <boot> <event> <text-sha256> <text-hex>
```

It refuses any UID but 2000 and any argument outside the request's strict form. It finds
`IActivityTaskManager.startActivityAndWait` by its exact parameter and return types, as
`core/java/android/app/IActivityTaskManager.aidl` 114 to 117 declare them (`pins.json` holds the
lines' digest), and refuses before any call when they differ. It then makes one call: caller none,
package `com.android.shell`, no feature, the explicit intent with `FLAG_ACTIVITY_NEW_TASK` and
`FLAG_ACTIVITY_CLEAR_TASK` and the request as typed extras, no type, result target or request code,
no flags or profiler, `ActivityOptions.makeBasic().setShareIdentityEnabled(true).toBundle()`
(`ActivityOptions.java` 1648 to 1672 and 2483 to 2484), and the request's user. This is the call the
shell's `am start -W` makes (`ActivityManagerService.java` 3865 to 3871), with identity sharing
added. The intent also carries a report binder for the activity's decision. `app_process` runs a
binder thread pool before the helper's main (`cmds/app_process/app_main.cpp` 79 to 83), and an
activity start refuses file descriptors in the intent but not binders (`ActivityStarter.java` 843 to
847). After a START_SUCCESS the helper waits at most 5 seconds for the first decision of known form
from an ordinary application UID of the request's user, and ignores any other report.

Its output is `andrix-notice-present-v2`, then `error=TOKEN` with status 2 to 6 before any start,
or the wait result's `result`, `timeout`, `who`, `total_time` and `launch_state`, the activity's
decision as `activity=presented`, `activity=refused:REASON` or `activity=unreported`, and the
reporting UID as `reporter=UID` or `reporter=-1`. Status 0 needs START_SUCCESS and a presented
decision, 9 START_SUCCESS and a refused one, 10 START_SUCCESS without a decision; 7 is another start
result, and 8 a wait result it cannot read. A presented decision says the fixture accepted the
request, never that a user saw it.

`notice_route.NoticeRoute` is the lab broker's notice adapter. `present(run, issue)` checks the
jar's pinned SHA-256 with `sha256sum`, runs the helper once for each required recipient with the
issue's exact fields, and checks the jar again. SUCCESS needs every recipient's reply to be
START_SUCCESS for the fixture activity with the presented decision of an application UID of that
recipient's user. REFUSED needs every reply to be a refusal: before a start, a failed start, or the
activity's refusal, a conflicting row included, with nothing shown and nothing written. Anything
else is UNRECOGNIZED. `visibility(effect, read, issue, binding)` reads `am get-current-user`,
`dumpsys power` and `dumpsys window displays`, runs `uiautomator dump` to a new unique path, reads
that whole file with `cat`, and reads the three states again. Its projection holds the current user
only when both reads agree; awake and focused only when both reads show the global wakefulness Awake
and the default display's focused window and focused app as the fixture activity in that user; the
text of the one challenge node; and visible only when the active window is the fixture's and that
node lies inside it with a nonempty area. A dump reported without its file, or refused, is
unavailable. Each call admits only the exact commands it is about to run.

`notice_reader.NoticeReader` reads each recipient user's provider whole and gives the broker's row
projections, keeping every row's bytes. A corrupt entry, or a row whose user, serial or UID is not
its store's, becomes a projection of no known form, so the broker refuses that read while still
pinning every row's first bytes. A partial write is never a row.

## Times, boots and recovery

The proven delivery is the completion of the first qualified independent visibility group, which the
lab broker records; the row's candidate time stays unqualified metadata until a guest qualification
shows the callback and visibility relation. Promoting the candidate is not implemented here. A
reread keeps the first proven time, and a fresh read recovers the receipt after a lost reply, a lost
coordinator process or a later framework instance of the same boot. Another boot, serial, ticket or
index never inherits it. Rows of another boot stay in the store and are kept by the broker as such.
Ordinary and emergency notice delays stay equal, with report and wait and no emergency notice grant.

## Producing the artifacts

The producer checks every pinned tool, every pinned framework source in `framework-api.json`, the
pinned Binder declaration lines, the manifest contract and the closed source set before it writes
anything. It compiles with javac `--release 17 -Xlint:all -Werror`, links with aapt2 against the
public SDK 36, dexes with D8 for API 36, aligns, and signs with apksigner with JAR and v4 signing
off; verification at SDK 37 requires the v3 scheme. It checks the signature, badging, the compiled
manifest, the APK's and the helper jar's DEX class inventories and their required and forbidden
references. The DEX, the aligned unsigned APK and the helper jar must equal `pins.json` whatever the
signer, so a primary's real build can be compared byte for byte.

Sign with a disposable key for host evidence only. The real signing is the primary's: supply that
key and certificate, and name the certificate's SHA-256 explicitly. The output directory must be
absent and outside the source and the tree.

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR="$SCRATCH/tmp" nice -n 19 timeout 360 \
  python3 -B produce.py --android-root "$ANDROID_ROOT" --source-revision "$REVISION" \
  --key "$KEY_PK8" --cert "$CERT" --signer-sha256 "$CERT_SHA256" --out "$ABSENT_OUTPUT"
python3 -B produce.py --check-output "$OUTPUT"
```

Each child runs with niceness 19, 2 GiB of address space, 90 CPU seconds and 90 seconds of wall
time, no cores and a 64 MiB file size limit, within 300 seconds overall. The output keeps every
tool's redacted argv, digests and raw streams, the inputs, the reproduced digests, the artifact
inventory and the closure. A failed output is kept as partial evidence and never resumed.

## Host tests

Run from this directory with bytecode disabled, a scratch TMPDIR, niceness 19 and no cores:

```sh
python3 -B -m unittest test_notice test_produce test_join
ANDRIX_NOTICE_JDK=<pinned JDK bin> python3 -B -m unittest test_java
```

- `test_notice`: strict row, key and listing framing against the committed Java goldens; provider
  replies of every other form; unreadable and overflowing stores never empty; the store binding of
  rows; the helper's arguments, command and reply forms, the activity's decision among them; a
  conflicting presentation refused beside the honest repeat; the route's jar checks and per call
  allowlists; the visibility projection with no focus, screen off, locked occlusion, an offscreen,
  ambiguous or old challenge, and a stale, missing or refused hierarchy.
- `test_java`, with the pinned JDK: the plain Java suite (request and row framing, actual against
  supplied user, the observed launcher, callbacks, the store's write order, repeats, a key holding a
  conflicting, corrupt or unreadable row refused before presentation, conflicting duplicates, failed
  syncs and every crash prefix with its restart, process restarts that keep unsynced names followed
  by a later loss, the listing, the provider policy, and goldens equal to the committed ones), with
  a changed copy of the disk model that takes an existing directory as durable as a control; the
  model suite, which runs the actual helper, provider, writer holder and disk against host stubs of
  the Android classes, the activity's reported decision in the helper's result and a restarted
  process's syncs included, where only the first report of known form from the recipient's app
  counts, with a helper without identity sharing and a Binder interface of another shape as
  controls; and the receipts against the accepted deployment reconciler, with changed copies of its
  delay, first receipt and budget rules that must each fail.
- `test_produce`: the manifest and compiled manifest contracts, the pins and the helper's pinned
  signature, and refusals before any output. With `ANDRIX_NOTICE_ANDROID_ROOT` it checks the pinned
  sources and the AIDL declaration; with `ANDRIX_NOTICE_BUILD` the artifact checks on a finished
  output.
- `test_join`: the route and reader joined with the lab broker's historical receipt path. It needs
  the broker's next campaign profile in `tests/component-lab` (a version 3 admission, the notice
  issue, the NOTICE_VISIBILITY action and the RECEIPT_EVENT read) and is skipped without it. With
  `ANDRIX_LAB_JAVA` and `ANDRIX_LAB_CLASSES` it also runs the accepted Java coordinator over that
  broker. The join wires the reader's recipients from the broker's issued notices.

A skipped case qualifies nothing. The stubs, the guest model and every changed copy are test code in
scratch, never a build input.

## What only a guest can show

- The helper's non SDK entry from `app_process`, its Binder call as the shell user, and that the
  activity then observes UID 2000 as its launcher.
- The report binder's way from the helper through the activity start to the app, the app's one way
  call back, and the helper's wait for it.
- What the screen shows when the activity refuses: the app sets no content, but the system may show
  its own starting window for the launch. The pinned source adds one only when the window policy
  reports the screen on (`ActivityRecord.java` 2302 to 2310), and whether one can wake the device
  from an always on display state is unconfirmed.
- Visibility on the locked and the unlocked display of each user: shown when locked over a secure
  keyguard without dismissing it, turning the screen on, the frame commit callback, focus.
- The shell forms: the helper's reply, `content query`, `dumpsys power`, `dumpsys window displays`,
  `am get-current-user` and the uiautomator dump and its file.
- The provider's runtime refusal of a foreign caller and its whole read as the shell user in each
  user, before and after unlock.
- The row's durability and readback through real Android loss: the fsyncs, the rename, a process
  kill, a framework restart and a kernel reboot.
- That the row's elapsed times and the broker's clock brackets are one scale, and the UI timing.

## Limits

- Every guest form here is source derived from the pinned tree and needs calibration.
- The challenge's visibility is read from the accessibility hierarchy. A node on the display can
  still be hidden by color, alpha or an overlay the hierarchy does not show.
- Two different requests for one key presented at the same time can both pass the activity's
  check, and both may be shown. The row written second is refused, as any conflicting row is.
- The helper's task flags end an earlier fixture activity in that user's task before the new one
  decides, so a refused request still ends an earlier notice of that user.
- The writer's latch lasts for its process. A new process may write again.
- A recipient store that cannot be read makes the whole read unavailable, for every user.
