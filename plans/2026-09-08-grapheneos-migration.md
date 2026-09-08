# GrapheneOS-derived base — isolated migration trial

## Accepted decision

After the [base assessment](../docs/grapheneos-base-assessment.md), the owner
approved GrapheneOS as Andrix's upstream Android/Pixel base and a bounded isolated
migration trial. The [architecture](../docs/architecture.md) records the sourcing
amendment. It supersedes the direct-AOSP-only restriction for this new trial;
it does not rewrite the old milestone's source provenance or results.

Android platform components remain ARM64/Bionic. Android identities, profiles,
init, Binder, ART, PackageManager, SELinux, verified boot and phone services remain
authoritative. The bounded owner environment, encrypted home and authenticated
read-only `/usr` remain the design. glibc and Android-backed Wayland remain
research candidates; neither is implemented or adopted here. Niri remains later.

This decision does **not** approve unlocking/flashing the daily-driver Pixel,
production keys, a supported release, new infrastructure, proprietary-input terms
acceptance, or a blanket hardening exception. Those remain their own gates.

## Initial source generation

Use the assessed public release as the first reproducible migration anchor,
not a floating branch or a reconstruction of its security-preview variant:

| Input | Pin |
| --- | --- |
| Public release | `2026081300` |
| Manifest repository | `https://github.com/GrapheneOS/platform_manifest.git` |
| Annotated tag object | `5189230024ffe0048e0c351d5101c6b3f8b43eac` |
| Manifest commit | `84536744f0c06cccbcfa2110e9c937671ddc3278` |
| `default.xml` SHA-256 | `c50f0096f538e604aa008e8ab4e3f1a3739f142c60c878a32f402c11eb406572` |
| AOSP base | `android-17.0.0_r1` |
| Repo tool | `v2.66.1`, commit `b85886fa9f5b4e2189cc5b2f40bd0a80459d4c77` |

The signed manifest binds all 1,108 declared projects to full commit hashes,
including adevtool and the Pixel kernel/prebuilt references. Source selection does
not establish vendor extraction, binary licensing, full-tree availability or
compatibility with the handset's current firmware. Before an actual release,
re-evaluate a current public source generation and its security coverage; this
anchor is not an indefinite update policy.

## M0 — manifest authentication and isolated initialization: passed

Following the official build guide, the public allowed-signers file was obtained
from `https://grapheneos.org/allowed_signers`, SHA-256
`344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0`.
Local `git verify-tag` accepted the exact tag for `contact@grapheneos.org` with
ED25519 fingerprint `SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM`.
A changed signed tag payload and an empty trust allowlist both failed verification.
This trust bootstrap uses the official HTTPS key endpoint; it is not an independent
phone identity or out-of-band key audit.

A new, separate source directory was initialized with the exact tag and pinned
Repo tool. Its manifest HEAD and local signature verification match the pins above.
Repo's warning that it is not tracking a moving branch is expected with the tool
revision pin; verification was not disabled. Command-local key configuration was
used, without replacing account-wide trust files. Private evidence
`grapheneos-migration-prep-20260908T162101Z` seals 26 review metadata files,
excluding the authentication Git object store.

At M0, only manifest/Repo initialization was complete. No AOSP checkout, existing
Andrix prebuilt, production key or phone was modified by initialization. Subsequent
source and product-configuration results are recorded below; they do not establish
a migrated runtime.

## M1 — complete and verify public source: passed

All **1,108** project HEADs match the authenticated manifest and passed tracked/
staged-cleanliness checks. The manifest/tag/Repo pins are unchanged. This generated
public manifest already omits the earlier AOSP Darwin-only entries; there are no
three additional exclusions to subtract. `repo list -p` was not sufficient: it
listed initialized metadata before four worktrees were populated.

The first sync failed before network progress because the inherited temporary
path exceeded Python multiprocessing's AF_UNIX socket limit. A short task-local
`TMPDIR` fixed that without changing Repo, pins or sandboxing. The next eight-job
sync completed 1,104 project HEADs, while four GitHub fetches expanded to full
branch/tag histories. That owned process group was explicitly interrupted; its
logs and missing terminal exit status are retained, not reported as a successful
sync. The exact four commits were then fetched with bounded `--depth=1`,
`--no-tags`, empty refmap and literal public URLs. All four succeeded. A full
**local-only** Repo sync then completed with exit 0 in 226.887 seconds.
Those four histories are shallow; their source revisions were not substituted.

The [source verifier](../scripts/proof/grapheneos_source.md) rechecked the complete
expected set and real SSH signature: `PASS_PINNED_SOURCE_HEADS`, 1,108/1,108.
An early incomplete-control returned FAIL with 189 matching projects; a later
in-progress inspection hit its caller's 180-second deadline and is not a pass.
The verifier now preserves per-project observations in a line-buffered ledger.
Its host tests and the product-source tests are included in **236 passing host
tests**. A cancelled writer delivered no changed files; primary implemented and
tested the verifier. No independent-review sign-off is claimed.

Private evidence `grapheneos-source-sync-20260908T164326Z` seals 92 regular files.
This is source authentication/revision/cleanliness evidence, not a full untracked
or prebuilt-materialization audit, a compiler result or runtime qualification.
The original AOSP tree and eighteen-file adaptation remain separate and unchanged.

A delayed worker caveat prompted a further verifier correction after M2. In a real
scratch Git repository, the original optional-locking-only profile executed a clean
filter which wrote a marker and normalized modified bytes into a clean result.
That defeats an unconditional read-only claim; it does not establish that the
actual platform check executed such a callback. The corrected helper isolates Git
configuration, disables external conversions/fsmonitor/hooks and lazy fetching,
and rejects unsupported filtered forms rather than invoking LFS. Real callback and
missing-promisor-object controls pass. All **1,108** projects and the signature were
reverified under that profile; the full host suite now passes **244 tests**. No
platform source, APEX, architecture or phone changes were needed. The original M1
and M2 evidence remains sealed; private correction evidence
`source-verifier-readonly-20260908T202514Z` seals 54 regular files.

The source-sync procedure remains:

- Sync into the isolated tree under the exclusive heavy-work lease with eight
  jobs and recorded storage/inode checks. Preserve original failures and use
  bounded, diagnosed retries rather than resetting or force-syncing unknown work.
- Verify actual checked-out HEADs against the authenticated manifest. Account for
  excluded host groups explicitly; declared project count is not a checkout pass.
- Record the exact Repo revision, manifest, groups, source status and any local
  Andrix overlay. Keep the old direct-AOSP checkout and frozen evidence intact.
- Do not run vendor generators merely to complete this gate: they can automatically
  download stock images. Review permissions and exact proprietary inputs first.

## M2 — attributable baseline and Andrix-minimal integration

Prepared product `andrix_gos_cf_arm64_only_phone-cur-userdebug` uses the existing
ARM64-only virtual board and the product-neutral Andrix APEX/init/`/usr` marker
layer. It does **not** import the old Cuttlefish network/RKP/provider RRO choices or
experimental WebView opt-in. Base platform source is unchanged; the separately
cloned Andrix producer is `be031f983a80dc99ee132f82f7379333ac18c2a3`. Existing lab APEX
keys were reused locally, without generating production keys or publishing private
bytes. The tracked key-module file was compared, not overwritten; an initial
no-overwrite guard stopped an incorrect assumption that it was an absent input.

Real `envsetup`/`lunch` and dumpvars completed with exit 0: Android 17 REL/API 37,
`arm64-v8a` only, `userdebug`, device `andrix_cf_arm64_only`. The selected shell
release is `cur`; the pinned release map resolves its parent to `cp2a`. A first
`TARGET_RELEASE` dumpvar was empty because the exact Make code deliberately clears
that variable during setup queries; the corrected observer records the shell
selection and generated release-config files instead. A real
`OFFICIAL_BUILD=true` configuration attempt failed at the product's explicit guard.
Those are product-configuration results, not a booted image.

The first `dev.andrix.usr` build then **completed with exit 0**, eight jobs,
1,271.119 seconds, ending `2026-09-08T19:56:52Z`. The build ran the host APEX,
linker-config and APEX SELinux checks. The frozen artifact was independently
checked with tools built from this new tree:

- APEX SHA-256: `96a27a78175991582615743489602e9a94771042f5820181a38f14639769f6aa`.
- Extracted hello SHA-256: `b0d1c7463bd31ff2e92cc39a9990eccaa9434e7f27c29d5548638ce8e77ab6df`.
- APK container and AVB payload signatures verify against the existing lab keys.
- Hello is AArch64 PIE, uses `/system/bin/linker64`, needs Android `libc.so`,
  `libm.so`, `libdl.so`, and has at least 16 KiB LOAD alignment. Linker metadata exists.
- A wrong expected container certificate, a corrupted signed container and an
  independently corrupted payload all failed closed. In the payload negative,
  the RSA footer remained valid but the data hashtree failed.

The post-build base-source check observed 1,107 clean matching projects and one
120-second `build/release` Git-diff timeout. That original FAIL remains; a bounded
single-project recheck with the same contract passed in 3.552 seconds. No tracked
source change or revision substitution was accepted. The separately cloned Andrix
producer is clean; the old AOSP adaptation still passes its original digest guard.

Private evidence `grapheneos-minimal-product-20260908T193006Z` seals 68 regular files.
This establishes a configured minimal product and a signed/verified **APEX**, not a
complete GrapheneOS-derived image, `/usr` activation, ordinary-app runtime isolation,
network qualification or a Pixel build/flash. No owner userland/ABI/GUI was added.

The untouched upstream Vanadium inputs in this anchor are **151.0.7922.137.0**,
version code 792213734, Config 200—not the prior Andrix 152 experiment. The four
ARM64/Config APK signatures verified against the same upstream certificate;
version inspection and signatures do not prove provider/runtime behavior. The
first signer invocation failed to find Java; the existing JDK25 wrapper succeeded,
with the original failure retained. No old userdata is being downgraded or reused.

Remaining integration gates:

- Build a complete image for the prepared ARM64 test product; do not silently
  substitute GrapheneOS's documented x86 SDK emulator or claim Pixel kernel
  features from Cuttlefish results.
- Establish the selected caiman vendor/firmware/kernel generation, rights and
  generated-file inventory before device builds. No reuse of Cuttlefish's kernel.
- Keep a small explicit downstream patch set. The assessment's nine clean file
  context checks are not build or semantic approval. Reuse recovery fixes only
  after combined-source review; omit already-superseded QSB/Wallpaper/Contacts
  changes and rebase endpoint/product behavior deliberately.
- Activate the verified `/usr` proof APEX in the new image and rerun the optional
  test fixtures. Do not start general owner packages, glibc or a GUI platform
  during baseline migration.
- Reconcile Vanadium source/artifacts, package identities, configuration trust and
  updates. Do not layer duplicate providers or substitute an unchecked APK.

## M3 — trust, networking and runtime gates

Before a connected migrated candidate, define honest Andrix identity and the
updater/app-catalog/service policy. A differently signed fork must not use the
official GrapheneOS updater as its update service. Endpoint replacements require
valid services and explicit deployment authority, not fake responses or silence.
Preserve TLS/CT/revocation and review Pixel RKP/eSIM/carrier paths rather than
blindly copying emulator-specific settings or stripping phone functionality.

Rebuild/re-run artifact, APEX, app-isolation, network and recovery oracles on the
new producer. Retain exact inputs, first failures, connected packet capture and
loss counts. Checked host code, compiler results, cryptography, emulated runtime,
native hardware and privacy claims remain separate.

A specific phone flash requires a signed/recoverable caiman image, current handset
firmware/rollback constraints, backups and explicit approval. The owner's locked
GrapheneOS daily driver stays unchanged until then. Development progress does not
confer official GrapheneOS security/attestation status on Andrix.

## M4 — first bounded owner-environment spike

After the minimal base is qualified, prepare the smallest useful owner workflow:
stable bounded identity, CE home, terminal/PTYS, native compilation/execution and
same-owner child debugging. Preserve ordinary-app negative controls, phone-critical
resource policy and explicit Android crossings. Reject a design requiring broad
ordinary-app hardening disable or an unbounded privileged terminal.

Exit criterion: maintained Pixel source inputs and a small, reviewable Andrix
layer suitable for owner computing. Real software migration, future ABI/window
research and release support remain deliberate follow-on work.
