# B2 ordinary subject

This is a disposable Android state fixture for the native account lifecycle reader step.
It is not native execution, an account authority, a lifecycle writer or a production package.
There is no Soong module, image build or `PRODUCT_PACKAGES` entry. Install the resulting APK
once as an ordinary test APK on a fresh, separately admitted disposable guest. Do not update an
old subject installation. The package and version are deliberately the old subject's identity,
not its old artifact bytes.

Compilation and host tests do not qualify Android behavior. Every Android output grammar here
is source derived and needs guest calibration before reliance.
See [EXPECTATIONS.md](EXPECTATIONS.md) for source lines and limits. No guest action is part of the
producer or observers. The selected notification preference still requires the full user lock.
[SETUP.md](SETUP.md) traces why the built in channel command cannot set it and why a separate
ordinary shell command with an explicit copy can. Neither root nor an app update is used.

## Fixed contract and choices

- Package `dev.andrix.proof.principalclosed`, versionCode 1, min and target SDK 37.
- One self instrumentation APK, testOnly, not debuggable, no backup or shared UID. No Activity,
  receiver, provider, launcher, custom Application, Internet permission or privilege adoption.
- Signer certificate DER SHA256:
  `874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3`.
- Exactly POST_NOTIFICATIONS, VIBRATE and RECEIVE_BOOT_COMPLETED requested. BIND_JOB_SERVICE is
  required by the exported ordinary JobService, not requested by the application.
- Two independent AndroidKeyStore EC P-256 signing keys. Aliases are `andrix_b2_state_ec0` and
  `andrix_b2_state_ec1`. Both sign SHA256withECDSA, without authentication, attestation or a
  StrongBox claim. Signing both is independently verifiable without retaining an AES secret.
- CE and DE `files/b2-state/canary.bin`. Bytes include schema, storage kind, package, UID,
  serial, setup token and distinct host chosen 128 bit dummy tokens. The host commits the full
  bytes before issue. DE also contains immutable `files/b2-state/setup.intent`.
- POST_NOTIFICATIONS granted with exactly internal flags RUNTIME_GRANTED and USER_SET, integer
  48. No other flag, including default, system, policy, compatibility or one time grant.
- Package `android:vibrate` mode ignore, with no nondefault UID VIBRATE mode. No vibration call
  is made, so no access or rejection timestamp is expected.
- Channel `andrix.b2.state`, name `Andrix B2 state`, importance 2, no sound, lights or vibration,
  badge enabled, no group or conversation. It uses explicit default audio attributes, usage 5,
  content 4, public/XML flags 0. The dump also shows default internal MUTE_HAPTIC bit 0x800.
  This avoids null audio attributes becoming defaults on XML reload. A separate ordinary shell
  command copies the remote channel before changing allow bubbles from -1 to 1. The existing
  NMS user update compares separate objects and locks just bit 256. This is a preference, not
  bubble UI delivery, and no notification is posted. The pristine baseline rejects any
  existing channel.
- Job 21802, default namespace null, service `.B2StateJobService`, persisted, one off, delayed
  2592000000 ms, 30 days, with no deadline or other requested constraint. Exactly two string
  extras bind setup and contract. Any callback writes an exclusive DE failure sentinel, logs a
  fixed failure line and returns false. It never reschedules. A callback fails the trial.
- Trial cap seven days from setup, stable RTC, UTC due time within at most 60000 ms of the
  original. A due job or clock jump is a confounded arm, not a pruning result. Elapsed displays
  rebase on boot and are not identity bytes. An identical illicit replacement has no scheduler
  generation identity, so command custody is also necessary.

The audio choice, exact token encodings, filename set, canonical contract and signature payload,
strict two key verification, bounded timing tolerance and public SDK producer are fixture choices.
They do not change the accepted lifecycle policy or authorize work after lift.

## Files

- `AndroidManifest.xml`, `res/values/strings.xml`: the isolated APK contract and label.
- `src/.../Contract.java`: exact bounded request, canary, intent and fixture contract encodings.
- `src/.../B2StateInstrumentation.java`: actual package, UID, serial, signer and unlock checks,
  before state capture, and explicit operation dispatch. Only initialize calls InitializeState.
- `src/.../InitializeState.java`: all local absence checks, exclusive durable intent, keys,
  canaries, channel and one schedule call. No rollback, cleanup, retry or resume.
- `src/.../ObserveState.java`: existing file, alias, key, permission and pending JobInfo reads,
  exact job validation, canonical payload and signatures. No notification preference getter.
- `src/.../StateFiles.java`: actual CE and DE roots, nofollow file opens, type and owner checks,
  bounded exact reads, exclusive writes and directory syncs. Only the explicit create methods
  write. Observe's call graph uses only constructor, exists, existing and readExact.
- `src/.../B2StateJobService.java`: unexpected callback sentinel and fixed log failure.
- `setup-src/.../NotificationSetup.java`: separate shell UID setup command, never an APK class.
  It rejects root/app UID and a local binder, explicitly copies the channel through Parcel,
  changes only that copy and calls the existing remote shell permitted user update once. Its
  acknowledgement is not an owner state oracle. Non SDK entry remains a guest admission gate.
- `produce.py`, `tools.json`, `setup-api.json`, `signer-certificate.pem`: standalone pinned
  producer, ten pinned setup API source references and public signing identity. The certificate
  is public. No private key is stored or generated by the producer.
- `protocol.py`: independently computed contract bytes, exact argv, strict signed reply schema,
  canonical payload reconstruction and independent OpenSSL verification of both keys.
- `observations.py`: complete capture envelope, permissionmgr, package and UID appops,
  notification channel, unfiltered jobscheduler, shell job lookup, dummy file hashes/metadata,
  PM surface and RTC assessment. Reuses the existing native schema and PM map readers, without
  accepting either native schema opportunistically.
- `stored.py`: strict selected records in decoded access, notification and job XML. No ABX
  decoder, service file writing, AtomicFile selector or stability assertion is hidden here.
- `owner_stores.py`: each owner's own role rule over a complete captured namespace, capture
  stability, binding of converter output to the raw digest, the subject's values from the
  selected records and from the owner dumps, their agreement, and the expected state of each
  setup stage. It judges one capture point and never issues a command.
- `ledger.py`: durable setup ownership per guest instance and package. It commits the exact
  issue bytes in a separate claim record before returning argv. Complete refuses any change
  after claim, including harmless looking JSON reformatting. UNKNOWN blocks progress. It never
  submits commands. Mandatory setup_jar provenance binds the separate artifact/copy capture.
  The read only `owned` check returns a ledger's verified request, contract and step records,
  refuses any drift and reports an incomplete, unknown or partially claimed setup.
- `fixtures.py`, `fixtures/compiled-manifest.txt`, `test_subject.py`: synthetic source templates,
  a pinned tool manifest dump shape, and host controls, including the old 1/0 result and reset.
- `owner_fixtures.py`, `test_owner_stores.py`: synthetic namespace captures and dumps in the
  frozen read grammar, and the owner store controls. They are not Android captures.
- `test_setup_command.py`: actual command source run against an explicit host object model,
  with aliasing and clone bypass controls. Not an Android IPC/codec/service qualification.
- `SETUP.md`: full setup path, rejected candidates, persistence, dump forms and remaining gates.
  Templates and the host object model are not guest observations.

## Produce the real artifact

The primary supplies the legitimately retained PKCS8 private key and matching PEM or DER public
certificate. Do not generate a replacement identity. The producer checks the certificate digest
before creating an output directory, log, temporary file or child process. It signs using a
snapshot of those checked public certificate bytes. Another signer is refused. A mismatched
private key is rejected by apksigner, never repaired or substituted.

Set absolute canonical paths for the Android root, source directory, output parent and custody
arguments. The output must be absent and outside source and toolchain. Supply the full source
revision from the frozen vehicle. Its value is recorded as a caller claim, not independently
verified by the producer. `inputs.json` records the actual file identities. Bind those hashes
and the revision independently in artifact admission.

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR="$SCRATCH/tmp" nice -n 19 timeout 360 \
  python3 -B produce.py --android-root "$ANDROID_ROOT" \
  --source "$SUBJECT_SOURCE" --source-revision "$SUBJECT_SOURCE_REVISION" \
  --key "$RETAINED_KEY" --cert "$RETAINED_CERTIFICATE" --out "$ABSENT_OUTPUT"
```

Use a bounded parent resource scope too, with no cores and enough virtual address space for the
JVM. The producer bounds each child to 2 GiB address space, 90 CPU seconds, 90 wall seconds,
niceness 19 and two reported JVM processors. The overall tool sequence has a 300 second limit.
It uses javac release 17, public SDK 36, D8 minimum API 36 and manifest SDK 37, as the earlier
standalone route did. This does not claim SDK 37 compile stubs were used.

Output includes `B2StateSubject.apk`, checked public DER, every tool digest, exact source hashes,
redacted command argv, stdout/stderr hashes and raw logs for every tool step, unsigned/aligned/
signed identities, exact DEX class definition inventory, ZIP inventory and closure. The separate
B2NotificationSetup.jar contains only its one setup class and is not included in the APK.
setup-artifact.json records its hash and role; setup-api.json records the source references.
All 21 child tool steps have captured output and digests. APK verification at SDK 37 uses v3.
An additional
artificial SDK 24..27 verification checks the requested v2 signature. It does not claim the APK
can be installed there. Full aapt2 badging and manifest inspection verify the component and
permission contract. Every input and tool hash is rechecked at closure. A failed output is kept
as partial evidence and must not be resumed. A disposable signer build is not this artifact.

## One setup, no retry

The host owns guest instance, boot/image and independent APK/UID/serial provenance. A challenge
alone attests none of these. Before installation prove absence of this package, and before setup
prove no native store, original APK/signer, ordinary UID in 10000..19999, user 0 and unlocked CE.
Use complete package/shared maps, not the subject's own reply as the identity oracle.

Before any initialize issue:

1. Commit `make_contract(uid, serial, setup, ce_token, de_token)` and exact byte hashes. Tokens
   are fresh 32 lowercase hex characters. H includes notification_setup=channel-bubbles-copy-v1.
   Keep the full original contract, never reconstruct later expectations from a reply. Freeze
   B2NotificationSetup.jar's hash from the producer and verify the uploaded ordinary shell copy
   at the fixed path before any selected effect. Supply independent capture hashes, including
   setup_jar, to ledger.prepare. Do not install that jar in an image or in the app's data.
2. Read complete service dumps and existing persisted siblings. Require POST denied with zero
   internal flags, no nondefault package or UID VIBRATE, no custom/deleted channel or nondefault
   notification preference, and no jobs in any namespace for this dedicated UID. Require both
   fixed `b2-state` directories absent. Unexpected defaults stop setup, not permission to clear.
3. Prepare the durable ledger and claim step 0 before sending its returned initialize argv once.
   A timeout, partial reply or transport uncertainty is UNKNOWN. The ledger name is independent
   of token, UID and serial changes, so a new token cannot evade an earlier setup attempt.
4. The subject repeats actual identity/unlock, empty alias namespace, absent file namespace,
   permission, effective operation, visible channel and all pending job namespace checks. It
   creates/fsyncs DE setup.intent before keys. Effects across service owners are not atomic.
   Any intermediate failure leaves state for assessment. Never initialize it again.
5. Verify the initial two signatures. This initialize reply has all before booleans false and
   the permission secondary read still false. It does not claim external setup is complete.
6. In order, claim and submit setup_commands(contract, initialize_nonce), ledger steps 1..4.
   Recheck the relevant precondition immediately before each effect. Before grant require denied
   with zero flags, before user-set require only RUNTIME_GRANTED, before appops require no
   package or UID VIBRATE override. Before the separate shell copy command require the created
   channel at -1/0 with stage='created' in both notification parsers, and the original jar hash.
   Never use cmd notification set_bubbles_channel, which mutates a stored alias and leaves lock 0.
   Verify the jar again after its one issue. Its bounded acknowledgement is stage=update_returned
   and state_proven=false; only Android owner read back proves the requested 1/256. Preserve argv,
   stdout, stderr and exit. Silence, a returned update or a valid acknowledgement is not success.
7. Independently read back every state and stored selected row. Verify the public keys and exact
   canary/intent hashes. Settle asynchronous service stores using stable bounded captures and
   the separately reviewed sync contract, then perform a clean reboot and observe again before
   native staging. Do not force service read-settings or write-settings, or edit their stores.

`ledger` stores issue and its exact byte commitment before submission, not afterwards. Completion
checks that commitment and the original argv from the prepared request, not a hash of whatever
issue bytes happen to exist later. A partial claim also consumes its issue name. Steps advance
only from confirmed successful outcomes and fresh precondition capture hashes. It does not judge
capture contents
or execute shell commands. The admitted vehicle must perform those assessments before claiming.
There is no retry API or compensating cleanup. A partial prepare consumes its name too.

Keystore listing is not a reliable service health oracle. The pinned provider hides metadata and
listing errors as absence. Uncaught getKey probes of both fixed aliases precede every write and
each generation, so existing selected private keys and service errors cannot authorize key
replacement. A pure certificate entry can still be indistinguishable from absence if the other
public reads fail silently. Enumeration cannot establish the absence of unrelated aliases under
that failure either. The fixed durable intent independently blocks every partial setup this
fixture creates. Fresh guest/package/UID provenance and complete provider diagnostics remain
mandatory. This does not qualify arbitrary preexisting namespaces under service fault injection.
See the precise source boundary in EXPECTATIONS.md before extending that claim.

## Observe without repairing

Use `instrumentation_argv` with operation observe, a fresh recorded 128 bit nonce, setup/contract,
phase, guest binding hash, UID, serial, both dummy tokens and both original public key hashes.
`--no-test-api-access` and `--always-check-signature` are explicit. No UiAutomation API, delegated
privilege, root entry into the UID, other target or deferred instrumentation bypass is used.

The only success envelope is exactly:

```text
INSTRUMENTATION_RESULT: b2_state_result=<one JSON object>
INSTRUMENTATION_CODE: -1
```

`protocol.PAYLOAD_FIELDS` is the complete ordered scalar schema. Java has the identical list.
Booleans are booleans, integers cannot be booleans, tokens and hashes are bounded lowercase hex,
no unknown/duplicate JSON fields are accepted, and all before booleans must be true on observe.
The four additional fields are key0/key1 SPKI DER and signature base64. Each public key must be
the exact canonical P-256 SPKI form and hash to its original anchor. Both signatures are strict
DER ECDSA and independently verified with OpenSSL, never only with the subject's own verdict.

Both keys sign `andrix-b2-state-v1\n` followed by every PAYLOAD_FIELDS entry in order as
`name=value\n`. Boolean text is lowercase. All values are validated before reconstruction.
This binds operation, challenge, phase, guest hash, actual identity, process/time, before state,
key hashes, file hashes and secondary permission/job answers. SPKI and signatures themselves
are not scalar payload fields. A self consistent replacement key cannot replace either anchor.
This is a transport bound experiment, not cryptographic device attestation.

Captures supplied to `observations` have exactly argv, stdout, stderr, exit_code and complete.
The transport must establish complete, with raw byte counts and sealed evidence. That boolean
alone cannot detect a dishonest capture. Functions require their exact command and expected exit,
complete LF terminated bounded output, selected nesting, identities and duplicate freedom. They
raise on failure or unavailable evidence. They never turn an absent or malformed result into an
empty successful state. Irrelevant global service sections are not claimed to be fully decoded.

Read both permissionmgr selectors and compare their returned facts. Pin migration version from
the baseline, not APK version. Require exact grant/flags and package ignore, with no UID VIBRATE.
Read the whole notification preferences section, exact UID and complete channel row, including
hex dump lock mask 100, decimal 256. Save remaining channel baseline fields and compare them.
Use unfiltered jobscheduler, not its package filter during deferral. Require one original default
namespace job, positive remaining time, correct component usability, no pending/active/history,
work or run counters. Controller references to waiting jobs are legitimate. Parcelled extras
only establish a representation, not marker contents. Typed persisted XML and admitted pending
JobInfo must prove the two original marker strings. Pin UTC due time, not elapsed display bytes.

Stored parsers accept complete decoded XML copies only. Refuse raw ABX rather than guessing its
codec. The existing permission store reader covers permission flags only, not the new package
operation or notification/job marker extraction. Do not combine main and backup as separate
current jobs. Do not write decoded XML back. Whole store file hashes are not selected state
invariants.

## Owner stores from captured namespaces

`owner_stores.py` reads each Android owner from a complete captured namespace, never from one
file. A capture holds an owner family's directory stat before and after, its `find` listing
before and after, and for each file a stat and `sha256sum` before and after its pull, the pulled
bytes and, for binary XML only, the booted image's own `abx2xml FILE -` output between those
bookends. `listing_argvs` and `file_argvs` give the exact command shapes. The vehicle owns the
transport and the order, and its closure binds that order to the capture sequence.

Each owner's own role rule selects the file its next read would use:

- Package Manager settings and user 0 restrictions: main, temporary backup and reserve copy.
  A backup is read first and removes the main, so a backup beside a main is a transaction.
- The Access store, which holds the permission flags and both operation modes: `access.abx`,
  AtomicFile `.new` and legacy `.bak`, and `.reservecopy`, a byte copy of the finished main.
  The reserve is read only when parsing the main fails, never when the main is absent.
- The notification policy: an AtomicFile base, `.new` and legacy `.bak`.
- JobStore: exactly `jobs.xml` and `jobs_UID.xml` in `/data/system/job`, each an AtomicFile.
  A `.new` or `.bak` whose base is absent is never read. One job identity in two files is
  refused, since JobStore keeps whichever file it lists first.
- The native store is captured as a tree for stability only. Its own copy rule belongs to the
  native readers and is never applied to another owner.

A transaction sibling, a missing or lagging reserve, or anything that moved or vanished during
the capture raises `Unsettled`: a later bounded observation round may settle it. An unknown
sibling, a link, an alias, a duplicate, a failed or incomplete command, a pull that is not the
stable file, or converter output for another file is refused. Binary XML needs its converter
output; text XML is read as captured and takes no converter run. The converter's codec is
qualified on the guest, not here.

Every owner's finished files are required. Package Manager and the Access store need their
main and reserve, the notification policy needs its base and the job directory must exist. An
empty family is refused, because those owners would read nothing and start from defaults. The
only absences a caller may admit, and only explicitly for the phase that expects them, are a
missing native store and a notification policy not yet written.

The Access document is checked against its complete grammar at every stage, whatever value
the stage expects: only the sections, owner elements and rows its parsers read, each once.
Android ignores any other element, so a value under one would establish nothing.

From the selected records `assess` reads the subject's values, and the same values from the owner
dumps: both permission selectors, both appops queries, the notification preferences, and the
unfiltered job dump with the guest wall clock. The disk record and the dump must agree, or the
point is unsettled. For the job they agree on its identity and its UTC due time within 60
seconds, never on elapsed display text. Each value is then compared with its setup stage:
`baseline`, `initialized`, `granted`, `user-set`, `ignored` or `retained`. A difference is named
for its finding, such as changed permission flags, a UID override, a reset or moved preference,
or a lost, replaced or executed job. The existing strict readers also run at every stage they
pin, so any other pinned field is caught. `comparable` and `selected_changes` compare a later
observation with an earlier one. They leave out what a designed phase changes without any
stored change: the job's component usability, false while deferred and true once admitted,
the parcelled or map display of its extras, and the notification permission suffix that only a
scanned package's row prints. Usability and the displayed extras are checked against each
phase instead. The rounds, the single sync and the stop rules of a settled read belong to the
vehicle; these functions judge one capture point.

## Guest sequence and limits

Android owners' dumps and persisted rows are the primary oracle. Judge them before starting
instrumentation and capture them again afterwards. Root reads only the exact dummy files with
hash, regular/nonlinked type, original UID/GID/mode and SELinux label. Bind actual independently
observed data paths. Reads do not authorize creating missing data. Instrumentation and key use
can change platform bookkeeping or key blobs. No claim of zero platform writes is made.

The clean lineage is eligible generation 1, user suspension generation 2, canonical version 1
lift generation 3, with the original lineage/principal/UID/serial/signer and no lingering old
record copy. Staging, replacement and OS switching belong to a separately admitted vehicle.
Require suspended B2 boots, two B1 floor boots, B2 return boots, lift, a further admitted boot,
and the lifted floor/return chain. Switch only OS state while preserving every guest persistent
disk. Do not restore userdata or APEX data snapshots. Keep all other plan layouts separate.

While mapped and deferred, do not launch the subject. Keys are not observable through ordinary
subject authority then. Root file hashes and Android service rows remain observable. Later fresh
signatures prove end to end key survival retrospectively, not continuous usability. The shell
job query can return unknown package while the registered persisted job remains. Its failure
must not be treated as job deletion. `job_state` requires the actual nonzero transport encoding
for service error -1000, not a guessed POSIX value.

Mapping loss is not this six state preservation arm. Permission and operation stores can drop
unknown mappings. Clear/uninstall/update refusals, force stop, allocator probes, retired or
malformed records, note storage and external data belong to separate arms. No reinstall, grant,
mode setter, channel recreation, key generation, canary restoration or schedule is allowed after
setup. Any mismatch stops and preserves the guest. Do not repair it to make B2 pass.

## Host tests

Run pure tests from this directory with Python bytecode disabled, scratch TMPDIR, niceness 19,
no cores, a bounded wall/CPU deadline and a 512 MiB Python address space ceiling:

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR="$SCRATCH/tmp" nice -n 19 timeout 120 \
  python3 -B -m unittest -v test_subject test_owner_stores
```

For the separate command source model, use a bounded 2 GiB parent address space, 120 CPU seconds
and a 150 second wall limit. PINNED_JDK_BIN names the supplied JDK's bin directory:

```sh
B2_JDK_BIN="$PINNED_JDK_BIN" PYTHONDONTWRITEBYTECODE=1 TMPDIR="$SCRATCH/tmp" \
  nice -n 19 timeout 150 python3 -B -m unittest -v test_setup_command
```

A skipped model is not its qualification. The test verifies javac/java digests, compiles the
actual command source and a clone bypass mutant with test only classes in scratch, then checks
copy/alias behavior, root/app UID, local/missing service, old preference and argument refusals.
It deliberately does not implement Android Binder, Parcelable or persistence. The real SDK
build is separate and excludes every test class from the APK and setup jar.

Tests cover two real host signatures, stale/tampered bindings, either replaced key, field/type/
duplicate/envelope refusals, contract and Java payload parity, source write path guards, exact
permission/op scope and masks, full channel parsing, unfiltered job identity/timing/component/
parcelled extras/execution exclusions, stored typed records and duplicate files, PM/native
schemas, dummy file metadata, setup ledger ownership and producer prewrite refusals. Owner store
tests cover each owner's role rule, transaction siblings, a backup beside its main, a missing or
lagging reserve, moving captures, refused evidence, converter binding, disk and dump agreement,
every setup stage and every named finding, required files and explicit absence, the Access
grammar at every stage, and the designed admission transitions. The tests never run an Android
runtime. Source guards and host crypto are not AndroidKeyStore or FBE evidence.
Guest shell entry and non SDK access, setup, output calibration, durability, service effects,
actual signer build, suspension, lift, reboot and B1/B2 reversibility remain guest or artifact
qualification gates.
