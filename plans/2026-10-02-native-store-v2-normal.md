# Version 2 native store in the normal image

Status: R0, the source, guard and host stage, is integrated and host qualified. R1, the normal
image, is built and its artifacts are inspected. R2, its first boot on a fresh guest, passed. R3,
the version 2 readers on staged layouts, passed. R4, the rollback to `78456b3` and back, passed.
A retirement and identity recovery step follows after the owner sets its policy.

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
  memory, and nothing calls the native principal manager's creation route. With no caller, R8
  removes that route from the normal image entirely, along with retirement, `currentIdentity`,
  initialization and the header writer. R1 confirmed this in final DEX: the manager keeps only its
  constructor and the static signer digest helper that Settings uses. Safety still rests on there
  being no caller, since adding one would bring the route back.
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

## R0 result

An implementation worker produced R0 in an isolated worktree. Independent review of its first
candidate found two gaps, both confirmed in source and fixed before integration: three tests that
guard the build scope and the factory fence had been deleted with the token, and the complete
stack rule lived only in the writer tool rather than at the shared fence. Review also added
hardening, and the escape rule now covers every production text.

- The old and new native patches differ by exactly one byte. The new adapted Settings equals the
  retired lab output byte for byte. Only the patch, Settings candidate and store helper pins
  changed, and the old and new store helpers compile to identical class files.
- The guard has seven rules, and twenty mutants each trip exactly their predicted rules. Every rule
  is tripped alone by some mutant.
- The `78456b3` sources, pinned from Git objects, and the current sources both read all 47 emitted
  version 2 layouts under `Format.V1` with holds kept but no pins, history or admission. The same
  layouts under `Format.V2` gave them, so the rollback assertions discriminate. Across the 45
  history layouts, version 1 recovery seeding deferred every mapped package and version 2 admitted
  them.
- The binding, history, counter admission and lab history runners passed under the required
  bounded scope with a real JDK, and the full host suite showed no failure beyond the base.
- Earlier failed runs are kept on record. They were harness causes: a fixture path over the
  Unix socket limit, unit time limits through disk sync latency, incomplete pinned inputs and an
  import path. The qualification runs used short tmpfs fixture roots.

These are host results, not Android, boot or power loss evidence. A version 2 run of the writer
fixture tests is due before the next lab image.

## R1 result

The normal image was built from the integrated source and its artifacts inspected. These are
compilation and artifact results, not Android boot, rollback or power loss evidence.

- The first build attempt failed. Its memory cap was sized from builds that skip Soong's full
  analysis, but this build must re-run it, because the lab's writer files present at the last
  analysis are gone. The kernel killed the analysis for memory at the cap, and the adaptations
  were reverted by hand once nothing remained running. The second attempt used a larger cap
  within the build budget and let a memory kill fail only the build step, so the build could
  clean up after itself. It built with a 47.4 GiB peak, then retired its producers and reverted
  its adaptations.
- Against `78456b3`, 18,440 of the 18,441 final DEX classes are byte identical, in the same order.
  Settings differs by one operand: the boot read loads `Format.V2` where `78456b3` loads
  `Format.V1`. The store, the CE, verity and payload companions and every other class are
  therefore exactly those of the inspected `78456b3` image, and the R8 removal record is the same.
- Direct checks of the final DEX: the store is constructed once, at the boot read. The manager is
  constructed once, where the Package Manager registers it, and the only call into it from outside
  is the signer digest helper. No other code names its class, so nothing looks it up. Its creation
  route is absent, as are retirement, `currentIdentity`, `initializeNew` and the header writer. The
  writer route is absent, the dump route is present, and the format enum is exactly versions 1 and 2.
- The expected difference from the lab image, the writer route alone, did not hold at the final
  DEX level. Whole program optimization made 31 classes differ between `78456b3` and the lab,
  including display, media and network classes. R1 differs from the lab in exactly those classes.
  Its Settings lacks only the eight writer route members the lab keeps, all listed in R1's removal
  record, and every member they share is identical.
- Images: the boot image, kernel, device tree and boot configuration equal `78456b3`'s. Both
  ramdisks change only build identity properties, and every partition and ramdisk identity carries
  the new build number. The kernel only boot image is byte identical, so its verified boot footer
  still names an older build. All 93 SELinux policy files are unchanged, all eight super image
  partitions equal the inspected standalone images, and the verified boot chain verifies with
  unchanged keys.
- For R4: both images run OS 17.0.0 with security patch level 2026-08-05 and the same verified boot
  rollback index, at the same locations, so rolling back to `78456b3` lowers neither. Its vendor
  partition carries the older vendor build identity, so the vendor fingerprint also changes between
  the two images.
- Each check first ran over the sealed `78456b3` and lab images, with positive and negative
  controls. That found three defects in the checks, and the first R1 run found one wrong
  prediction, about the lab comparison. All are kept on record. Each corrected check was set from
  the sealed images before it ran unchanged on R1. Dexpreopt files and whether the emulator
  enforces rollback indexes were not inspected.

## R2 result

A fresh disposable guest booted the version 2 normal image for the first time. Its fingerprint,
SELinux enforcement and `services.jar` digest were R1's.

- Ordinary installs placed the two observer APKs and the separately signed subject. Each observer
  initialized its dummy key once. A clean reboot preserved the APK paths and bytes, the UIDs, the
  full package map, the subject's data directories, and the observers' keys and canaries.
- The native store dump read exactly the missing store before the installs, after them and after
  the reboot: a missing header, incomplete enumeration, an unknown counter, creation not ready,
  cursor 10000 and no holds.
- The writer route is absent at runtime as well: on both boots the Package Manager shell refused
  the writer command as unknown.
- Nothing overrode a setting. The animation scales read the same at the start and the end. No
  grant, clear, reinstall or key restoration was issued, and every command fell within a fixed list.
- With a missing store, version 1 and version 2 images dump alike. The version 2 evidence here is
  the `services.jar` digest, tied to R1's final DEX inspection.
- The vehicle was derived from the lab's executed fresh baseline vehicle by exact substitutions,
  then reviewed independently. Review found that the first draft's writer refusal check matched a
  substring, and that the second kept an inherited instrumentation option that writes global
  animation settings. Both drafts were staged, never launched, and are kept on record. The final
  assessment derived its verdict again from the raw records, including a signature check of every
  instrumentation reply.

The subject has no instrumentation, so its claims cover only its APK, UID, map and data
directories. This is not a native store read, write, rollback, durability or power loss result.

## R3 result

The normal image read four staged store layouts, one per disposable guest: an empty version 1
store on R2's guest, and on three fresh guests baselined by R2's exact procedure, with the same
UIDs and user serial, a bound `CREATING` reservation, a `LIVE` header with its slot and body, and
the reservation again with its binding naming user serial 1.

- Each layout was generated for its guest and checked against the independent oracle. The empty
  store's header is version 1; the others' headers are version 2. Each was staged into genuine
  absence with Package Manager's writer quiesced, through exclusive pending names, synced writing
  descriptors and no clobber renames, with exact owners, modes and labels and a setup sync. Each
  staging ended with exact, stable captures of the whole namespace, without fs-verity flags, and a
  QMP quit.
- Every cold dump read a valid header, a known counter, complete enumeration, creation ready and
  cursor 10000. The empty store showed no holds and stayed the 70 byte version 1 pair. The
  reservation held the subject's app ID with a missing slot, and the live layout with a valid slot,
  both pinned and mapped to the subject. The subject was admitted with its original path, UID, map
  and APK bytes.
- No store change was observed on the tested cold boots. Across two or three cold boots per guest,
  every node's bytes, inode, owner, mode, label, size, type, links, flags and modification and
  change times equaled that guest's staging record and its previous read.
- The serial control dumped exactly like the reservation, so the dump alone cannot tell them
  apart. Its scan deferred the subject: the boot log names native UID ownership recovery and
  retained code, `pm path` found nothing, the admitted package list omitted it, and the setting
  kept its UID and code path. Its code bytes and data directory structure stayed unchanged.
- In a boot that first showed the exact hold, the held subject's update, data clear and two
  uninstall attempts, one with a wrong version, were refused. The update named an unquiesced
  native account, the clear reported failure, and the uninstalls had no upstream reason in the log.
  The subject's measured state, its data directory trees including times, and the app directories
  stayed unchanged within that boot, and a further cold boot read the same store and subject.
- Finding: during both clear attempts, ActivityManager logged a force stop for the subject before
  Package Manager's clear call. The Package Manager barrier does not prevent that earlier action.
  Other ActivityManager effects were not measured, and `pm clear --cache-only` was not tested.
- The vehicles were derived from the lab's executed staging protocol, writer session and cold
  reader by exact substitutions. Independent review shaped the design and four vehicle revisions.
  Each admission derived its phase from the reviewed generators again, and each closure derived
  its verdict from the raw records.

These are staged layouts, not writer output. They carry no fs-verity, which the reader does not
consult. The subject's data trees were compared by structure across boots and with times only
within one boot. QMP stops are not power loss. No native call, publication, designation or
initialization ran. This is not a writer, durability, rollback or power loss result.

## R4 result

The last version 1 normal image, `78456b3`, read version 2 stores on Android, and the normal image
read them again afterwards. This supports the rollback contract for the two staged version 2
layouts, in both directions, under a reflash model.

- A fresh guest booting `78456b3` passed R2's procedure as the first boot control: ordinary
  installs, keys and canaries across a clean reboot, the exact missing store dump and the refused
  writer route. Staged by R3's protocol with an empty version 1 store, it then read VALID, counter
  known, creation ready, cursor 10000 and no holds, as the version 2 image does.
- Three fresh version 2 guests, baselined by R2's procedure, were staged by R3's protocol: the
  empty version 1 store as the switch control, the bound `CREATING` reservation, and the `LIVE`
  header with its slot and body. Each first cold read was as in R3.
- With each guest stopped, its OS partitions were switched to `78456b3`'s. The host built a sparse
  copy of the guest's own disk image in which only boot, init_boot, vendor_boot, the four vbmeta
  images and super were replaced. It checked the replaced ranges against the sealed images and
  against the control guest's own assembled disk image, and the kept ranges against the guest's
  image. It checked that the guest's overlay, which holds every guest write and which the host never
  wrote, presents exactly those bytes, then exchanged the disk images. The switch back restored the
  original disk image byte for byte. R1's image inspection had found the same boot image and
  SELinux files in both builds, and vbmeta images signed with the same key at the same rollback
  index. The two builds also ship byte identical host packages, bootloader included.
- Each switched guest booted `78456b3` over its existing userdata. Package Manager logged one
  upgrade from the version 2 fingerprint. The KeyMint inputs stayed equal: orange boot state,
  unlocked, the same KeyMint and Gatekeeper selections, release and all three patch levels. The
  vbmeta digest equaled the control guest's, and the trial found both observers' keys and canaries
  intact.
- Under `78456b3` the empty store read as on the control guest, and the subject stayed admitted.
  The reservation and the live layout read as unsupported footprints: header UNSUPPORTED, counter
  withheld, creation not ready, enumeration complete, and the subject's app ID held without a pin,
  its slot MISSING for the reservation and VALID for the live layout. The scan deferred the subject
  with both log lines: no path, not admitted, its setting kept at UID 10148 with its code path and
  APK, and its data directories' structure unchanged. A second `78456b3` boot read the same and
  logged no upgrade.
- Switched back, the version 2 image logged one upgrade from `78456b3`, read every store as before
  the rollback, and admitted the subject again with UID 10148 and its original code path. A further
  ordinary boot read the same.
- No store change was observed. At the start and end of each cold read, every node of the store
  matched staging in bytes, inode, owner, mode, label, size, type, links, flags and modification
  and change times, within each guest. Each cold read ended with packages.xml unchanged across
  Package Manager's write delay and no backup file, then one guest sync before the QMP quit, and
  no later boot read a settings backup or reserve copy. fsck found nothing to repair on any boot.

The switch replaces the OS partition bytes of a stopped guest. It models reflashing those
partitions, not an over the air update, a slot switch or a bootloader's rollback protection, which
stays a release gate. The guests were unlocked and both images had equal patch levels by
construction, so a locked device and a patch level downgrade were not tested. Package Manager
stayed live between the sync and the quit, and the settle step watched packages.xml only, so the
state after each guest's last phase is not shown. Two version 2 layouts were tested, once each.
The held package refusals were not tried under `78456b3`, and that rollback leaves no history and
the deferred app cannot run are inferences from source. The layouts were staged, not written by
the writer, and this is not a power loss result. Only `78456b3` is a supported rollback target. No
native call, publication, designation or initialization ran. The first switch on the control guest
was refused before any change, because the switch tool's listing followed Cuttlefish's dangling log
symlinks; the tool was corrected and reviewed before the retry.

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
  the deliberate exceptions to producer binding. These are fresh guests staged with R3's qualified
  protocol; R3's guests are not reused. Boot the version 2 image, then the sealed
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
- Host facades are not Android evidence. R2 to R4 qualify the tested layouts on Android; the other
  layouts rest on R0's host model.
