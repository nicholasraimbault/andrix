# Version 2 native store in the normal image

Status: design accepted after three independent review rounds. R0 is next; no source, guard or
image has changed yet.

## Decision

On 2026-10-02 the owner approved making version 2 the native store format of the normal image,
with native execution, the native factory, retirement and release still off. This follows the
completed [header recovery lab](2026-09-28-native-header-recovery-lab.md). It replaces the
earlier standing rule that production constructs `Format.V1`. A retirement and identity recovery
step follows later, after the owner sets who may designate, suspend or retire a native account
and authorize its data disposition.

## What changes

The normal image constructs its native store in exactly one place: the boot read in the adapted
`Settings.readNativeIdentityStoreForBoot`. That construction passes the literal
`NativeIdentityStore.Format.V1`. The only code change is that literal becoming `Format.V2`.

Comments that would become false are corrected without changing their line counts: the store
helper's class comment (lines 51 to 53) and format enum comment (lines 121 to 122), and the host
Settings facade's comment. The store helper is pinned again in the native profile. Compiling the
old and new helper must give identical class files, so its final DEX is expected to be unchanged.
R0 checks the class files and R1 checks the DEX.

No property, setting, stored value, reflection or enum lookup selects a format. No initializer,
factory, designation interface, retirement, release or native execution is enabled.

## Runtime meaning while creation is off

- The normal image reads the store once, at boot. Every later consumer uses that cached view:
  pin restoration, the shared history view for scanning and recovery seeding, the identity
  predicate, the binding lookup, creation readiness, the app ID hold barrier, the recovery view
  used by the app data, storage event, install, delete and removal paths, and the diagnostic
  dump. None creates a second store instance. The reload after a commit exists only for a
  writer, and no normal image caller reaches one.
- Version 2 headers are supported instead of unsupported footprints. A bound `CREATING` entry
  whose slot is genuinely missing restores a PENDING pin with its original ID. A body under a
  version 2 `LIVE` header restores a PENDING pin too. In both cases the package is admitted only
  when its installed identity matches the recorded binding; otherwise the pin stays and the
  package is not admitted while held. Under the version 1 format the same layouts keep only
  unpinned holds and defer the package.
- Version 1 stores read exactly as before and stay version 1. The format reaches loading only
  through the header version ceiling, and reads never write. Under `Format.V2` a header write
  changes version only when it adds a truly new bound entry. No normal image path writes the
  store at all: `initializeNew` has no production caller, the release finish only updates
  memory, and nothing in the normal image calls the native principal manager. R8 removed only
  the retirement, `currentIdentity` and initialization paths. The manager's creation route stays
  in the normal DEX with no caller, so this safety rests on there being no caller, and R1 checks
  that in final DEX.
- With a valid, unblocked store whose copies agree, the dump reports a known counter and
  creation ready. Creation stays off only because no caller exists. A held, admitted package runs
  as an ordinary app and cannot be updated, uninstalled or cleared while held.

## Recorded preconditions and how each is met

Earlier plans set what a reviewed enable must join.

- **Binding preservation, transition checks and encoded size admission.** The
  [creation binding step](2026-09-27-native-creation-binding.md) and its corrections are host
  qualified. The lab observed the actual writer leave a bound `CREATING` reservation, restore it,
  rebind the same ID and publish the predicted bytes.
- **Supported readers.** The single boot read and its cached consumers above. Their Android
  behavior under `Format.V2` is qualified in R2 and R3, not inferred from the lab image.
- **Rollback contract.**
  - The supported rollback reader is exactly the last version 1 normal image, `78456b3`. R0 runs
    the `78456b3` sources, pinned from Git objects and equal to the current code, under
    `Format.V1` over every version 2 layout, and R4 observes that image on Android.
  - Under it, every version 2 header copy is an unsupported footprint. The header reads
    UNSUPPORTED, the counter is withheld, creation is not ready and no body or reservation
    history exists. Holds remain, without pins. A mapped native package is deferred: its
    setting, code, data and UID are kept in memory at that boot, but it is not admitted, so the
    app cannot run. The store bytes stay unchanged, because no normal image path writes them.
  - Moving forward, the version 2 image restores the pins and admits a matching package again,
    provided the package setting persisted across the rollback boot. R4 observes whether it does.
  - Every other image is an unsupported rollback target, because only `78456b3` receives Android
    rollback evidence. Gated images from `e3ad881` through `89491b9` had narrower host or Android
    reader evidence. Earlier images may treat version 2 as damage, and images without the store
    ignore its holds.
  - In the lab every guest stays bound to its exact producer, except the one deliberate R4
    rollback guest. A release must enforce the rollback floor through verified boot rollback
    indexes. That is recorded as a release gate for the
    [Pixel integration plan](2026-09-21-pixel-integration.md), not implemented here.
- **Recovery ownership.** Package Manager owns bindings, counters and holds. Every restored
  state waits for an explicit owner action that the normal image does not offer yet:
  - A PENDING pin, restored from a reservation or a body, is rebound only by an explicit
    designation owned by the future account controller.
  - A PENDING creation can instead be withdrawn only through the separate cancellation join,
    which does not exist yet.
  - A RETIRING restore, a deferred package and a hold without history stay as they are until
    the retirement step defines who may retire or repair them.
  - A matching package runs as an ordinary app and is frozen against update, uninstall and
    clearing. A package whose signer or serial does not match is not admitted while held.
    Nothing reuses a UID or issues a new ID.

## Source and guard changes (R0)

- **Source.** The Settings literal changes, and the comment corrections above keep their line
  counts. The native profile pins the new Settings candidate, patch and store helper. Every other
  framework output stays identical. R0 records that the new adapted Settings equals the retired
  lab output byte for byte, and that the old and new native patches differ by exactly that one
  byte. The store helper's comment change is recorded separately, with its identical class
  files.
- **Tree precondition.** The Android tree must be in its standing state: CE and package verity
  adapted, the native, payload, writer and format adaptations reverted, and Settings upstream.
  That state was observed on 2026-10-02. The new tools refuse a tree that holds the old adapted
  bytes; such a tree needs a revert with the old tools or a reviewed manual repair.
- **Production format guard.** It is inverted and anchored:
  - exactly one construction, inside the Settings hunk's `readNativeIdentityStoreForBoot`,
    between that method's exact construction and persistence anchors, passing `Format.V2`. The
    patch is read per file section, so a construction in another file's hunk cannot pass;
  - `Format.V1` refused in every production text, so a one token patch that reintroduces it
    fails under any name;
  - no mention of `NativeIdentityStore` in production texts outside the native helpers and the
    native patch;
  - value, property, settings, reflection and enum selection refused, with the retired lab
    tool's wider selector set scoped to native sources, plus `EnumSet`, `MethodHandle`,
    `VarHandle` and `Unsafe`;
  - the format enum's definition pinned, so its versions cannot be swapped;
  - any legitimate selector match in native sources fails the check, and a change to the
    selector scope needs review;
  - mutants that each assert the exact rule they trip: a regression to `V1` at the site, a second
    construction with the allowed literal, a framework construction, a construction in another
    file's hunk of the native patch, a one token `V1` patch at two paths, value and property
    selection, a reflective field write, `EnumSet.complementOf`, an enum version swap and the
    construction moved outside the boot method.
- **Lab format token retirement.**
  - Its dependents in the live tree are the shared framework fence
    (`native_principal_pins.lab_format_state` and `inspect_files`), the image build fence
    (`android_lifecycle.inspect_lab_native_format` and its `lab_native_format` record), the lab
    history runner (its strict, source, guard trip, pinned and store fixture checks, its
    predictions file and pure suite list), the token's own tests, the lab history tests, and
    three documents: the lab plan, the lab history README and the patches README. The search
    covered the tool and module names, the fence function, the record key, the state name, the
    command flag and the file stem. The only private vehicle using it is the historical `23cede6`
    lab build; a later lab image gets a new reviewed vehicle.
  - The lab history runner keeps its generator, predictor and rehearsal. The token's subject
    constants function moves into that runner. The generator's subject and signer, and the
    observer's fixed signer, are compared with values parsed from the pinned writer fixture, not
    with another hard coded copy.
  - The complete stack requirement moves into the writer fixture's lab admission. Under lab
    admission the native companion, the owner lifecycle CE companion, and package verity with its
    payload sync companion must all be exactly adapted. The writer fixture itself must be exactly
    upstream before an apply and exactly adapted before a revert; a check accepts either exact
    state, and a partial writer refuses everything. A repeated apply or revert therefore refuses
    where the current tool treats it as a no operation; its tests change with it.
  - This changes `native_identity_writer.py`, so its pin in the lab history runner changes. The
    writer fixture, its profile and its patch keep their pins.
  - The token's tool, tests, profile and patch are then removed. They stay recoverable from git
    history and from the sealed `23cede6` producer records, which this step does not change.
  - The lab plan gets a dated note rather than rewritten history.
- **Host qualification.**
  - The host Settings facade defaults to `Format.V2`, and a source check ties that default to the
    literal extracted from the patch's boot construction, so the two cannot drift.
  - Runs carry one of three labels: production (`V2`), the rollback reader model (`V1` reads) and
    archived baselines. Version 1 writer runs model no shipped reader; they are labelled legacy or
    retired.
  - The implementation names which harnesses run under each label. That covers the store,
    persistence, presence, manager, recovery boot fragment, binding, history and counter admission
    suites, the writer fixture tests and the lab rehearsal.
  - The rollback model is pinned to the `78456b3` Git objects with their hashes, as the existing
    archived baselines are. It reads every emitted version 2 layout, including `LIVE` with its
    body, and asserts the effects above. Scan refusal is asserted in the Settings facade, and
    package deferral in the history harness that runs the Settings seeding.
  - Mutants and exact baseline comparisons run under the required resource scope.

## Android stages

Each stage needs its own admission.

- **R1, normal image.** Build the normal image from the integrated source. Final DEX must show the
  one boot construction using `Format.V2`, the writer route absent, the dump route present, no
  call site of the manager's creation route outside the manager, the same R8 removals as before,
  and the CE, verity and payload companions intact. Compare `services.jar` with the sealed
  `78456b3` image's: the expected difference is the Settings token alone, with the store class
  byte identical, since every other companion is unchanged since that image. Compare it with the
  lab image's too: the expected difference is the writer route, with the same debug metadata
  allowance for shell inner classes. Storage is measured fresh. Bulk space no longer meets the
  earlier build admission, so frozen artifacts go to root under a fresh budget that also covers
  R3 and R4.
- **R2, fresh baseline.** A fresh disposable guest with the two observer APKs and their UIDs,
  keys and canaries, and the subject APK from its sealed producer, whose certificate matches the
  generator's fixed signer. Subject claims cover only its APK, UID, map and data directory,
  because it has no instrumentation. A clean reboot follows. The store is missing, so the dump
  must read `cached_header=MISSING`, `cached_enumeration_complete=false`, `counter_known=false`,
  `creation_ready=false`, cursor 10000 and no holds, as the earlier lab baseline observed.
- **R3, version 2 readers.**
  - Inputs: generate exact layouts for this guest with the existing generator and predictor, from
    its own package map and user serial, checked against the runner's independent layout oracle:
    an empty version 1 store, a bound `CREATING` reservation, and a `LIVE` header with its body.
    Loose predicted records are assembled into exact main and reserve copies with no backup or
    seed.
  - Staging: the reviewed protocol staged only an empty version 1 pair and an empty slot root into
    absence, with PMS quiesced. R3 extends it to version 2 headers, a slot directory and two body
    files, so its vehicle needs its own review. Each layout uses one fresh store, with exact
    owners, modes and labels and an existing slot root.
  - Expected: the empty version 1 store reads valid, with a known counter, creation ready, no
    holds and its bytes still version 1. The reservation shows a pinned hold with a missing slot,
    and the live layout a pinned hold with a valid slot; both read a valid header, a known counter
    and creation ready. The subject is admitted with its original UID and map. Bytes are unchanged
    across two cold boots. Update, uninstall and clear of the held package are refused.
  - A negative control with a serial mismatch keeps a pinned hold, because restoration ignores
    the serial, while the scan refuses admission. The generator cannot produce a signer mismatch
    without a new reviewed input path.
  - The lab guest's disks are not copied. That keeps the lab guest bound to its producer, and
    keeps lab history out as a confound.
- **R4, rollback.** One dedicated disposable guest per layout, each holding a version 2 store,
  the deliberate exceptions to producer binding. Boot the version 2 image, then the sealed
  `78456b3` image twice, then the version 2 image again, for a `CREATING` reservation and a
  `LIVE` layout. Expect the rollback effects above, unchanged bytes and a persisted package
  setting, then admission with the same UID and map on the forward boot, with the observer
  APKs' keys intact.
  - `78456b3` has never booted. Its first boot needs a fresh control, or a boot failure is
    classified as an image fault, not a rollback result.
  - Its sealed partition identities are checked first, since an older vendor build identity was
    once found and fixed only in a working tree.
  - Each image switch changes the fingerprint, so Package Manager runs its upgrade path. The
    vehicle records both images' fingerprints, security patch levels and verified boot rollback
    indexes. Differing patch levels could make KeyMint upgrade or refuse keys; that is general
    Android behavior, not yet verified here.
  - The vehicle defines how userdata carries across the two images.

## Limits

- Native execution, the factory, designation, retirement, release and initialization stay off.
  This step qualifies a format and its readers, not native account activation.
- No physical power loss, writer crash durability or mid write interruption is qualified.
- Rollback to any image other than `78456b3` is unsupported, and release enforcement of the
  rollback floor is a later gate.
- The dump shows neither the pin phase nor the header version, and stays unchanged. PENDING stays
  inferred from source, and the version is read from the store bytes.
- Host facades are not Android evidence. Until R2 to R4 pass, the change is implemented, not
  qualified on Android.
