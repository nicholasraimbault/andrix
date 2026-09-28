# Optional lab preparation for V2 header only recovery

Status: the separately compiled lab image on `23cede6`, including counter correction `78456b3`,
passed static checks and a fresh Android baseline with a clean reboot. The native store remained
MISSING. No native designation, preparation or V2 publication was issued. Production stays
`Format.V1`; native execution and the factory stay off. Later store operations still need their
own admission. This follows the
[historical identity step](2026-09-28-native-creation-history.md).

## Why a lab arm is needed

B2 restores a complete CREATING header without a body as a PENDING pin, and an explicit
designation rebinds its original ID. Host facades qualified that. The earlier
[writer lab](2026-09-26-native-writer-qualification.md) exercised version 1 publication, same
handle retry, reply loss, an access refusal and cold rebinding of a published body. It never left
a header only creation. A later Android lab needs the actual writer to leave exactly that state,
a cold restart, and an explicit rebind that publishes the original ID.

The lab can run only after the separate counter admission correction is reviewed, qualified and
integrated, and after the normal image compiles with it. That correction changes the store and
the normal profile only; the pinned adapted Settings stays the input of this format.

## One lab format token

A separate profile and patch under `tests/native-identity/lab-history/` change exactly one byte
of the exact adapted B2 `Settings.java`. The literal `Format.V1` of the boot store construction in
`readNativeIdentityStoreForBoot` becomes `Format.V2`. Nothing else changes: no path, file,
boolean, property, setting, value or reflection based selector, and no production V2 site. A pure
proof checks that the output differs from the input in that one byte, inside that construction.

The profile pins the pinned upstream Settings `bff2de57`, the adapted input `d18ffbd1`, the lab
output `301cb589` and the patch `ad603677`. It records `lab_only`, `native_execution_enabled`
false, `format` V2 and `production_format` V1. It also pins the unchanged writer profile and
helper, and the fixture's subject, signer, version and user, which the tool rereads from the
helper. The tool validates the current normal native profile with every source hash it requires,
and pins only its Settings rows. A store only correction therefore keeps the lab format
admissible, while a changed Settings refuses it until the patch is regenerated and reviewed.

The files stay outside `patches/`. That is not a hidden guard bypass. The unchanged production
format guard scans that directory and refuses a copy of this patch there, under any name.

## One admission decision over the complete stack

`native_principal_pins.inspect_files` recognizes one more Settings state, `LAB_FORMAT_V2`, only
by its exact bytes derived from the exact adapted Settings. The native companion reports that
state as itself, never as `ADAPTED`, and as `PARTIAL` unless every other native file is exactly
adapted. Known upstream and adapted bytes never load the lab files. Unknown bytes always refuse,
also when the lab derivation is unavailable: a missing profile or patch, a patch timeout or a
missing tool gives the same refusal, never a fallback.

One decision in `native_lab_format.require_admission` admits the state. Without it, the decision
returns absent before reading any companion detail. With it, only explicit lab history admission
over the complete lab stack admits it: every other native principal file exactly adapted, the
exact adapted writer fixture, the owner lifecycle CE companion adapted, and package verity with
its payload sync companion adapted. The shared fence calls it first, as the outermost lab layer.
Normal admission, including the writer tool's own lab admission, always refuses the state with a
request to reverse it first. A partial stack refuses every inspection, check, apply and revert.
There is no force option; recovering from a partial stack is a reviewed manual checkout repair.
The existing `inspect` signature and writer admission line are unchanged, and nothing inspects
recursively.

`scripts/proof/native_lab_format.py` needs `--lab-history-format` for every action and a fresh
unsealed evidence path outside the source tree and the repository. Apply needs the same complete
stack, with this format as the native state it adds. Apply after the normal CE, package verity,
payload sync and native companions and then the writer fixture. Reverse this format first, while
every companion is still complete, then the writer fixture, then the native and payload
companions. Every normal tool refuses while the format is present. Producer liveness is not
detected: retiring the build producer scope, and capturing it empty, before any apply or revert
is the caller's precondition, as is the admission of any effects.

## Controlled input and predictions

A host generator writes one empty version 1 header pair and an empty `slots` directory with a
fresh random lineage, through the actual record codec. Its bytes equal what the store's own
initialization writes for that lineage. A predictor writes, outside any store layout, the V2
CREATING header with the complete binding of principal ID 1, the published LIVE header and the
generation 1 body. It uses the fixed subject and signer and the lineage, app ID and user 0 serial
from the lab's own records, which the observer validates against the recorded generation and the
acknowledged original prepare. Existing, aliased or partial output, unknown modes and invalid
identifiers refuse before any file exists, also without Java assertions. There is no
PackageSetting, UID allocation, user data, key file, initializer or publication. The output is
lab input or prediction, never authority.

## Host rehearsal

The rehearsal runs the unchanged writer fixture, the real manager and store, and the host PMS
facades with `Format.V2`. A generated empty store is selected and prepared, which captures ID 1
and the facade app ID, serial and signer. The slot root changes from 0700 to 0500. The unprivileged
process keeps real read and search there and has no DAC override. The first commit returns false
with the same original handle. The store then holds exactly the complete V2 CREATING header under
counter 1, with no body, slot directory, seed, backup or extra file.

There is no retry before the modeled cold restart. The restart restores PENDING from the header,
and a new fixture instance refuses the old one. The mode after this modeled restart is captured first,
then the exact original mode returns while the new fixture is idle, before `select-rebind`, and
is captured again. `select-rebind` and `prepare` keep the same ID, record and handle, and the
commit writes the generation 1 body and the LIVE header under counter 1. A cold reopening restores
that body PENDING with the original ID. Controls cover a lost commit reply, recorded only by its
issued ledger line and reconciled by status, error, exception and observation faults after the
actual writer returned, retained nonces, intents and attempts, no select-new fallback or
initializer after the restart, and a changed APK signer that cannot rebind. Nothing injects a
PackageSetting, UID, pin, history or issuance.

Its byte copies of the store are byte oracles only. They carry no modes, owners or SELinux labels,
and no hash of them proves durability. Modes are observed separately on the live store.

The facade installs the existing fixture tests' synthetic certificate, the bytes 1, 2 and 3, with
the digest `039058c6`. That is not the fixture's development signer `874cedf4`, and no host result
is a claim about the Android subject's certificate. The generator's prediction method accepts the
rehearsal's signer set for this host check; its command line always predicts with the development
signer from the profile. This is a host facade rehearsal. It is not Android, SELinux, crash or
storage evidence.

## Observers

`writer_observe.assess_commit` qualifies positive commits only and is unchanged. The new
`lab_history_observe.assess_false_commit` covers the header only arm. It requires the recorded
select-new intent, the original instance, nonce and selected identity, one acknowledged prepare,
exactly one completed commit attempt that returned false, a fresh PENDING observation and no
historical positive acknowledgement. The issued ledger kind, not the reply, decides between the
direct reply and explicit status reconciliation. The result never infers that nothing happened or
that no reservation exists. Pending, ambiguous, foreign or changed scopes refuse, as do stale
observations, exceptions and a replayed commit.

An unresolved request is retained on purpose as an UNKNOWN envelope keyed to its issued ledger
record: kind, original instance and nonce. The captured selection is a required input. The
envelope keeps the issued commit when no reply, an unavailable reply, an unparseable reply or a
foreign reply arrives. It takes fields only from a reply in the issued scope. The envelope
fingerprints the supplied reply and stderr text encoded as strict UTF-8; it retains neither. Before
assessment, the caller retains the raw captured stdout and stderr with the issued ledger. A
fingerprint matches that capture only after strict UTF-8 decoding without newline translation. It never invents an acknowledgement or authorizes a retry or replay. A claim that the
original operation was retained after a lost or unavailable reply also needs a later actual
status reply to the same issued instance and nonce that still shows the original request. Header
and filesystem bytes are separate observations, compared exactly with the lab input and
predictions.

## Guarded host qualification

Run `python3 -B scripts/proof/native_lab_history.py --evidence NEW.json --work NEW_DIR
--pinned-framework PINNED` inside the required bounded scope with a JDK on PATH. Read only source
checks run first. Without 2 GiB of memory, zero swap, 2 CPUs, 256 tasks, disabled core dumps and a
JDK, the run reports NOT_RUN and creates and starts nothing. A guarded run writes only below
`NEW_DIR` and the evidence file. Every compiler and JVM it starts, including those of the suites
it runs, has its working directory inside `NEW_DIR`, a heap of at most 256 MiB, no HotSpot performance data,
fatal error and compiler replay logs in `NEW_DIR/jvm` and no core requested. A JDK phase checks
that the JDK applies each of these options before anything compiles, and stops the run otherwise.
Nothing silences diagnostics. Java, the compiler JVM and suite JVM options are checked. A work
path with whitespace, a quote or a percent sign is not run. Host
facade stubs may overlap only in the reviewed `android/util/Log.java`. One report is shared by every
phase: each phase's record is installed before it works and each
finished step is checkpointed, so a compiler log survives a later timeout. A stopped run keeps
every finished record and problem and the stopped command's streams, is NOT_COMPLETE and retries
nothing. Its phases are the source checks with the pinned rebuild and guard trip, the generator
controls, the rehearsal with its transcript, snapshots and modes, the unchanged writer regression
and the pure suites.

The runner compares the primary arm's empty, CREATING and LIVE header and body bytes, plus the
predicted files, with an independent layout oracle. Lost reply, fault, fallback and changed signer
stores also have the separate Java codec assertions. The oracle is evaluated at the fixed
golden values, at a fresh command line lineage with the development signer from the profile, and
at the rehearsal's actual lineage, app ID and serial with the independently computed host test
signer. The oracle is test only; the actual codec alone
produces lab input and predictions. Expected outcomes are in
`scripts/proof/native_lab_history_predictions.json`. They are predictions, not results, and a
modeled transcript checked against them is no Java qualification.

## Observed host qualification

The primary composed these test tools with the counter corrected sources and ran them under an
actual 2 GiB resident limit, zero swap and core dumps, 2 CPUs and 256 tasks, with JDK 25. The
complete run passed all six phases in 40 seconds with a 180 MiB peak:

- Java, compiler and suite JVM flags and temporary directories were checked before compilation.
- All seven generator controls passed, with command line refusals checked with assertions enabled
  and disabled, and independent layout bytes at fixed and freshly generated inputs.
- The unchanged fixture and actual manager and store passed ten rehearsal controls, emitting
  41 real reply labels and the prior issued ledger record. This is host execution, not Android.
- The unchanged writer regression passed all three tests.
- The lab format, runner and observer suites passed 38, 21 and 16 tests. Existing observer, lifecycle,
  writer, pins, verity, Package Installer and history suites passed too, including the pinned
  Package Installer derivations. No required tests were skipped.
- The complete counter runner, with its B2, B1 and B0 regressions, also passed on the composed sources.

The first candidate admitted a lab token over incomplete CE or Package Installer companions on
check and revert. Review caught this before integration or Android use. Its corrected decision
now requires the full stack for every admission of the lab state. Earlier synthetic transcripts
and runs with skipped pinned checks are not substituted for the complete qualification above.
The original failure and partial checks remain separate records. After explicit integration,
the complete lab runner and the full counter runner passed again on Main. The latter includes
the B2, B1 and B0 baselines, matrices, readers and mutants.

## Observed Android compilation and static checks

The first lab job compiled Android, then failed its subject APK guard. The Soong helper used the
platform testkey, not the unchanged writer fixture's fixed developer signer. Nothing was booted
or installed. The expected signer was not changed. The earlier writer trial had used a separately
sealed SDK artifact, so the corrected definition names that exact subject producer separately
from the image and its two observer APKs. It neither resigns an APK nor reuses an old guest.

The first job recorded image hashes but lost its host and APK hash rows when the guard failed.
A corrected build was used rather than claiming historical provenance from hashes taken later.
Every corrected copy has a synced hash record before later guards. That build passed in 228
compiler seconds, with a 29.1 GiB peak inside the unchanged 54 GiB, 8 CPU scope. All producers
retired before source reversion. CE and verity remain applied; the lab, writer, native and payload
companions were reverted. The first job remains failed.

Preflight also found an older vendor build identity in the normal image. The Make property rule
reads build number and fingerprint files without listing them as dependencies. Its cached vendor
property file could therefore survive a later build. Only that captured derived working file was
archived and removed, then regenerated by the unchanged rule. No property value was edited by
hand and no old image or seal was changed. All eight corrected partition identities are current.
Build labels alone are not proof of a component's provenance.

The separate bounded artifact checks established:

- Actual final DEX constructs `Format.V2` and retains the fixed subject writer route, its root and
  debug gates, shared history and the selected counter constraint. Shared R8 refusal helpers
  unconditionally throw the expected exceptions.
- Header protection precedes destructive writes, and the Package Installer reverse copy still
  syncs its writing descriptor before close and success.
- At class level, 9,655 existing classes are byte identical to the normal counter build. The only
  semantic changes are the Settings token, shell dispatch and added fixture. Shell inner classes
  are semantically identical after accounting for serialization and debug metadata.
- Retirement, `currentIdentity` and store initialization paths were removed by R8. Their compiled
  source contracts are not runtime qualification, and this image exposes none of those routes.
- The eight active partitions unpacked from the actual super image equal the inspected standalone
  images byte for byte. The kernel boot image, device tree and boot configuration match normal.
  Ordered ramdisk entries differ only in build identity properties. All 93 SELinux files match.
- The lab AVB chain verifies with the same algorithms and reported key identifiers as normal.
  This is a development artifact check, not production signing custody or runtime verified boot.

The build manifest alone is not a guest admission. The artifact assessment is separate, and fresh
userdata selection, APK installation, live permissions, effective security state and cold recovery
remain untested. Every refused checker and incomplete preparation remains separate evidence.

## Observed fresh Android baseline

P1 passed on a fresh guest, not an earlier trial's userdata. Before boot, the generated 8 GiB
userdata was read completely as zero, the composite selected it instead of the built userdata
image, and the working raw super matched the statically checked expansion. Overlay backing chains
were checked before launch and matched the actual frozen QEMU executable, drive arguments and
captured objects.

The guest had the expected services bytes, SELinux enforcing, a debug build and no new native
entry binaries. Only the writer's `info` command was used. Ordinary installs established the two
observer APKs and the separately signed subject. Each observer initialized its own dummy key
once. A clean reboot preserved the original APK paths and bytes, assigned UIDs, full PMS map,
subject data directories, keys and canaries. The writer's new server instance was observed, but
the native store stayed MISSING with an unknown counter and no holds.

The subject has no instrumentation, so this proves none of its key continuity or permissions.
Its installed APK bytes and Android mapping were checked; the live native selection's signer
check belongs to the later writer phase. No native selection, preparation, header staging or
publication occurred. A final explicit setup sync preceded host scope shutdown. This is neither
a native writer durability test nor a claim of clean guest power off or physical power loss.
The VM scope closed and its state and original logs were preserved for the next admitted phase.
Earlier UNKNOWN requests from other guests were not replayed or requalified.

## Planned Android lab stages

These stages need a later separate admission. None ran here.

- P0: the normal B2 image, with the counter correction, compiled and guarded, and that correction
  qualified and integrated. The lab image differs from it only by the writer fixture and this
  format token. Its image, fingerprint and manifest are marked lab. Final DEX shows `Format.V2`
  and the fixture route in the lab image, and `Format.V1` with no route in the normal image.
- P1: a fresh disposable guest, never an earlier trial's. Baseline the ordinary APKs, their PMS
  maps, dummy keys and canaries. The UID store and peer observers keep their own original keys and
  canaries. The subject package has no instrumentation, so claims about it cover only its APK,
  UID, map and data directory, unless an existing actual method supports a key control.
- P2: one host generated empty V1 input, staged only after the store's genuine absence and
  captured PMS writer quiescence, with exclusive writing descriptor and namespace checks. The
  staged layout is exact: owner 1000:1000, directories 0700 and files 0600. Its expected SELinux
  context comes from the pinned policy; capture and verify the actual labels after staging. An
  explicit setup sync precedes any PMS resumption. Boot again after staging,
  because PMS caches its store, and require a VALID header with counter 0, creation readiness, the
  generated lineage and no holds before P3. This qualifies no production initializer.
- P3: change the slot root from 0700 to 0500 with read and search kept, check and sync that
  before the writer runs, and capture its owner, mode and label. Confirm the actual system server
  UID 1000, no DAC override and no MAC denial on the store path. The actual writer is then refused
  creation of the slot directory by DAC, and the first commit leaves the complete CREATING header
  without a body. Assess the reply with the false commit observer and the store bytes separately.
  Never sync afterwards to qualify the writer.
- P4: capture, quiesce, then stop the whole guest uncleanly through QMP, without a sync afterwards.
- P5: cold boot. Capture the persisted slot root mode first. Require the same bytes, ID, UID, map,
  PENDING phase, counter and header history. Restore the exact original mode while the new fixture
  is idle, before `select-rebind`, and capture it. This is the owned fault protocol, not a security
  relaxation. Then rebind explicitly through the new fixture instance.
- P6: the body is published and the entry is LIVE.
- P7: a cold bookend reads the body and restores PENDING with the original ID.

Every stage captures actual Android bookends: writing descriptors, modes, owners and SELinux
labels, apart from byte captures. Directory timestamp retention is not an oracle, and no hash
proves durability. Nothing is granted, and no ordinary permission is claimed. No regrant, revoke,
reset, reinstall, key restoration, deadline extension, or signature, SELinux, verity, resource or
animation relaxation may make a stage pass. Any deviation or refusal stops the run and retains the
unknown outcome, its handle, nonce and obligations. Earlier trial outcomes, including an unresolved
cold key observation, stay as recorded and are not replayed here.

Lab user data is only ever relaunched with the same sealed image and host input bytes from its
recorded producer, using the recorded overlays without reassembly or reset, unless a separately
reviewed update says otherwise, and never with an older reader from before the version gate. All
version 2 guest data, keys and evidence are kept under the standing preservation policy. A
disposable guest holds no daily user data; that is no deletion authority.

## Limits

- No production rollout, enable or native activation claim. The format token exists only in a
  marked lab image.
- No mid write crash, physical power loss, whole installer, native Stop, permission or retirement
  qualification.
- The host rehearsal uses facades and an injected directory mode, not Android storage, SELinux or
  crash behavior. The Android lab uses the actual writer's DAC refusal, which is an access refusal,
  not a writeback failure.
- The tools do not detect a live build producer. Producer retirement stays an operator check.

The complete host run also requires `ANDRIX_SOURCE_ROOT` to name the pinned Android source
checkout. This supplies the existing Package Installer derivation controls. Any skipped required
suite case makes qualification fail; a zero test process exit alone is insufficient. The
checkout is read only input to these tests, not authority to apply a companion.
