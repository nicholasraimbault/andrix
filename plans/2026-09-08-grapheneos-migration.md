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

**Only the manifest/Repo initialization is complete.** The 1,108-project source sync,
GrapheneOS build and migrated runtime checks have not run. No AOSP checkout,
existing Andrix prebuilt, production key or phone was modified by initialization.

## M1 — complete and verify public source

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

- Determine the initial ARM64 test/product configuration; do not silently substitute
  GrapheneOS's documented x86 SDK emulator for ARM64 or claim Pixel kernel features
  from Cuttlefish results.
- Establish the selected caiman vendor/firmware/kernel generation, rights and
  generated-file inventory before device builds. No reuse of Cuttlefish's kernel.
- Keep a small explicit downstream patch set. The assessment's nine clean file
  context checks are not build or semantic approval. Reuse recovery fixes only
  after combined-source review; omit already-superseded QSB/Wallpaper/Contacts
  changes and rebase endpoint/product behavior deliberately.
- Add the signed `/usr` proof APEX and optional test fixtures first. Do not start
  general owner packages, glibc or a GUI platform during baseline migration.
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
