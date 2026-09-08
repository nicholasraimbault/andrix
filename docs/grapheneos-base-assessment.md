# GrapheneOS as Andrix's Android/Pixel base

## Recommendation

**GO for a bounded GrapheneOS-derived migration trial.** For a Pixel-first Andrix,
this is a better use of development effort than independently maintaining the
missing Pixel hardware layer on plain AOSP. It lets Andrix concentrate on its
owner computing environment while following a coherent, maintained Android/Pixel
platform rather than assembling selected security changes piecemeal.

This is an assessment and proposed direction, **not adoption, a build result,
security certification or flash approval**. The accepted architecture still says
direct AOSP until the owner explicitly amends that sourcing decision. Android as
the phone/APK platform, bounded ordinary owner processes, encrypted home, trusted
read-only `/usr`, and explicit authority crossings do not need to be abandoned.
Neither glibc nor Wayland implementation is adopted by changing the upstream base.

## Evidence and limits

Assessment anchor: public GrapheneOS `2026081300`, manifest commit
`84536744f0c06cccbcfa2110e9c937671ddc3278`, with AOSP default
`refs/tags/android-17.0.0_r1`. This is the same AOSP tag as the existing Andrix proof.
The [caiman inventory](../plans/2026-09-08-caiman-readiness.md) records the public
manifest/tag, device-tool, stock-build reference and kernel metadata. The `01`
security-preview variant is not reconstructed from the public `00` source tag.
An assessment anchor is not a policy to stay on that release indefinitely.

Read-only inspection covered:

- The revision-pinned manifest: 1,108 entries, of which 996 use AOSP, 110 the
  GrapheneOS GitHub remote and two its GitLab remote. That counts repositories,
  not changed lines, maintenance cost or security coverage.
- All 18 source files touched by the current Andrix platform adaptation, sampled
  at their exact GrapheneOS/AOSP revisions; selected policy, app-control, spawning,
  allocator, updater and prebuilt-import sources.
- Official GrapheneOS build/features/usage documentation, distinguished from
  pinned implementation and from actual device behavior.
- `git apply --check` context trials in external scratch, **without applying a
  patch**. An initial in-worktree trial skipped paths; verbose checks exposed that
  invalid observer. Corrected trials require `Checking patch`, reject `Skipped`,
  and include a failing missing-file control. The original attempt is retained.

No GrapheneOS platform checkout/sync or active source import, build, vendor
extraction, license acceptance, phone connection/unlock/flash, endpoint deployment
or active AOSP change occurred.
No claim of runtime compatibility follows from source/context checks. Two
independent reviewers were cancelled without complete usable reports; the findings
below are primary-inspected evidence, not an independent-review sign-off.
Private evidence `grapheneos-base-assessment-20260908T075950Z` seals 212 regular
files, including exact source samples, diffs, corrected context checks and failures.

## What GrapheneOS supplies — and what it does not

It maintains a coherent AOSP-derived platform, Pixel support, kernel changes,
security hardening, applications and release machinery. Its pinned `adevtool`
workflow prepares device/vendor integration from stock inputs and checks generated
modules against file-hash specifications. The caiman reference uses the caimito6.1
kernel/module family; our Cuttlefish6.12 kernel is not a substitute.

That addresses substantial continuing work: firmware/HAL integration, properties,
SELinux/VINTF/sysconfig, device regressions and adaptation to new Android releases.
It does **not** eliminate proprietary firmware/driver dependencies or give Andrix
an automatically supported phone. We still have to merge, build, qualify, sign,
publish, recover and support our derivative. Vendor-input rights and redistribution
terms need their own review; adevtool's MIT license does not license its inputs.

Upstream update cadence is valuable only if Andrix follows it. We cannot promise
every official GrapheneOS assurance, app-attestation acceptance, or early security
preview fix merely because our public-source base is related. Keep the fork delta
small and review updates against exact tags, not an unbounded moving branch.

Compared alternatives:

| Direction | Assessment for the present Pixel-first goal |
| --- | --- |
| Direct AOSP + our own Pixel integration | Most control over the starting platform, but we own the absent device layer, its continuing maintenance and selected hardening integration. Still possible; not the preferred allocation of effort. |
| Coherent GrapheneOS-derived base | Best fit: maintained Pixel/AOSP platform, closely aligned security/privacy defaults, and reusable Andrix work. Requires explicit owner-environment integration and downstream release ownership. |
| Another broad-device Android distribution | Could make sense if broad hardware coverage became the priority. No new comparative security/runtime audit was performed here; this is not a blanket claim that other projects are unsafe. |

## Owner Unix fit

**No architectural incompatibility was established in the sampled source.** That
is narrower than proving an owner environment works. Its implementation is still
needed whichever Android base we choose.

| Requirement | Evidence and implication |
| --- | --- |
| Android stays native | Bionic, Android linker, Binder, identities, profiles, PackageManager and system UI remain the platform. GrapheneOS is not a Linux VM/distro layer. |
| Read-only signed `/usr` | The APEX payload and packaging/init approach are reusable work. Rebuild/relabel/revalidate on the new product; prior signatures, mount and app-denial results are not a migrated-image pass. |
| Compile and execute owner code | Modern ordinary apps still face AOSP's `execute_no_trans` neverallow on app data. Turning off a GrapheneOS DCL toggle does not remove that policy. Use a deliberately bounded owner identity/domain and owner-data types, not an ordinary APK masquerading as a general Unix account. |
| Debug owner programs | Pinned controls include per-app native-debugging policy, with system-app restrictions immutable in normal user builds. A same-owner child debugger needs scoped policy/flag handling; it does not need blanket cross-app `SYS_PTRACE` or ordinary-app sandbox weakening. |
| JIT/interpreters/plugins | Memory code loading, storage code loading and WebView JIT are distinct controls. Executing a compiled file is not permission to make stacks/heaps executable. Any needed owner JIT capability must be scoped and tested; keep platform/app protections otherwise. |
| Stable CE home, PTYs and sessions | Android storage/UID/SELinux/init primitives remain. There is no demonstrated GrapheneOS-specific blocker in this sample, but CE unlock/relock, devpts/FD access and the session broker have not been implemented or tested. |
| Background owner work | Android process, battery, suspend and memory-pressure rules remain relevant. A non-root owner environment is not an exemption from phone-critical resource management. |
| Isolated untrusted jobs | Keep these outside the broad daily owner identity. Owner-executed code intentionally shares owner authority; app/job isolation still needs its own proved boundary. |

### Concrete hardening observations

Pinned `SELinuxFlags.java` describes per-app/per-user/per-process flags for memory
execution, execution of app-data files, ptrace and allocator selection. It says the
process attribute is writable only by the trusted spawning domains, not app zygotes
which execute untrusted code. Zygote passes the flags through
`selinux_android_setcontext2`. These are not arbitrary app preferences a compiler
process can clear for itself.

`AswDenyNativeDebug`, `AswRestrictStorageDynCodeLoading` and
`AswRestrictMemoryDynCodeLoading` distinguish system apps, explicit system allowlists,
user-app defaults and compatibility settings. `AppSwitch` resolves immutable values
before defaults/manual flags. Therefore **simply installing a privileged terminal
APK and enabling compatibility mode is not the proposed owner design**. Neither a
global weakening property nor a platform-signer stand-in is an acceptable shortcut.

The sampled `app_neverallows.te` retains the modern-app private-executable
restriction. The sampled `untrusted_app_all.te` is byte-identical to our pinned AOSP
base. Much of this integration work is therefore an Android boundary we already
knew about, not a new impossibility introduced by GrapheneOS.

The pinned spawning code uses real `execve`/`execveat` for Java/native app spawn
paths, rather than showing that native process creation is generally prohibited.
It does not by itself establish arbitrary owner `fork/exec` compatibility.

## glibc and Wayland implications

**glibc remains the leading compatibility research candidate, not an adopted ABI.**
GrapheneOS's hardened Bionic integration is not automatically inherited by a glibc
process. The pinned hardened_malloc README supports a glibc allocator-replacement
path, but explicitly distinguishes that from custom Android/Bionic integration.
Its generic Linux/glibc dependency baseline and Android GKI support are different;
neither proves the complete glibc-on-caimito6.1 combination.

Research must cover loader/library namespaces, signals/threads/TLS, DNS/NSS/locales,
filesystem assumptions, seccomp, MTE/allocator behavior and updates. Keep platform
components Bionic. Do not solve compatibility by replacing Android's linker/libc
or globally disabling hardening.

An Android-backed Wayland path for **individual application windows** is still a
separate integration project. Keep the existing launcher, WindowManager,
SurfaceFlinger and Kotlin/Compose APK ecosystem. Rendering, input, IME, clipboard,
accessibility, resize and lifecycle crossings require explicit capabilities.
Nothing in this assessment selects GPUI, niri or a replacement desktop/compositor.

## Existing Andrix work: reuse and rebase

The corrected mechanical trial found **9 of 18 file patches with clean context**.
That is not a build or semantic approval. In particular, all six recovery-related
file patches checked cleanly; five of those GrapheneOS files were byte-identical
to the AOSP baseline. `DeletePackageHelper` differed but accepted the checked hunk
contexts. We must still review and test the resulting combined behavior.

| Work | Disposition |
| --- | --- |
| Six recovery/AtomicFile files | Carryover candidate; not already supplied by this sampled public release. Retain first failures, lifecycle limits and tests; requalify on the new base. Upstreaming generic fixes is a possible maintenance reduction, not an action performed here. |
| `/usr` APEX, hello and app-boundary fixtures | Reuse source/tooling as the smallest initial Andrix addition; rebuild and rerun artifact/runtime oracles. |
| DNS/DoT/diagnostic/tethering policy | Rebase semantically. GrapheneOS has configurable GrapheneOS/standard endpoints and different non-Google fallbacks; copying our old literal substitutions would be wrong. |
| Certificate Transparency | Rebase against the configurable downloader. The sampled base has GrapheneOS and standard Google URLs; preserve signatures, key allowlist, installation and freshness behavior. |
| QuickSearchBox omission | Already superseded in the sampled handheld product. Do not reintroduce it merely to reapply an old patch. |
| Wallpaper Google autoVerify filter | Already removed in the sampled manifest. Drop our duplicate change. |
| Contacts directions | Already uses the `geo:` path. Drop the duplicate change. |
| WebView product import | GrapheneOS already selects `TrichromeWebView` and includes its browser/app ecosystem. Reconcile our custom packages/signers/version/policy rather than layering duplicate providers or substituting an unchecked prebuilt. |
| DSU/attestation URL changes | Both checked mechanically, but semantics still matter. The sampled DSU loader's support predicate stays false; a clean patch does not prove a working DSU consumer. Do not silently enable/skip its security checks. |
| Cuttlefish endpoint RROs/RKP settings | Review per target. Cuttlefish-only overrides are not phone defaults. In particular, do not blindly copy the emulator's blank RKP hostname onto a real Pixel. |

Keep the old direct-AOSP manifest, adaptations, frozen images and evidence as a
separate baseline. A rebase never retroactively qualifies a different producer.
GrapheneOS's documented SDK emulator path is not proof our ARM64 Cuttlefish target
inherits its Pixel kernel features; preserve the artifact/ISA distinction and
check actual kernel support rather than silently substituting x86 evidence.

## Networking, identity and release responsibilities

GrapheneOS helps substantially, but **GrapheneOS-derived is not an Andrix no-Google
verdict**. Exact sampled examples:

- `ConnChecksSetting` defaults to GrapheneOS; native/Java checks retain a selectable
  standard Google path. NetworkDiagnostics uses Cloudflare addresses where AOSP
  used Google addresses; that is different from Andrix's reviewed configured-DNS
  policy, not an automatic equivalent.
- CT has a GrapheneOS-hosted URL and a standard Google alternative.
- Remote key provisioning defaults to a GrapheneOS proxy URL. A proxy changes the
  network path; it does not establish that no device-derived payload reaches an
  upstream service. The Pixel attestation/RKP policy must be reviewed explicitly.
- Official usage documentation distinguishes optional sandboxed Play from the OS
  backend and describes proprietary eSIM management and conditional carrier
  provisioning paths. Keep phone functionality and user app choice; neither strip
  those blindly nor assume all carriers satisfy our runtime boundary.

We own the policy for upstream-hosted, owned and optional endpoints. Do not merely
rename domains without providing valid services or weaken TLS/CT/revocation to
obtain a quiet capture. Reuse the connected fixture and retain drop counters.

The pinned Updater config points to `https://releases.grapheneos.org/`. The official
build guide explicitly warns that a differently signed derivative must not use
that update endpoint. Before any connected distributable candidate, define its
updater inclusion, URL and trust configuration. That is not permission to deploy
new infrastructure during this assessment.

The sampled AppStore module is a privileged preprocessed APK import with a
permissions file. Its catalog, prebuilt provenance, update trust and relationship
to our separately signed Vanadium components need review. They are not automatically
our package/release channel.

Use distinct Andrix release identity and keys, preserve upstream attribution and
licenses, and do not impersonate official GrapheneOS or promise acceptance by its
attestation ecosystem. Some source identifiers describe capabilities rather than
branding; audit them instead of blindly stripping names or faking support.
Verified boot, OTA/APEX/APK keys, recovery, key continuity and firmware rollback
constraints remain deliberate release decisions. The owner's locked daily-driver
phone stays unchanged until a specific inspected image and restoration plan are
approved.

## Proposed decision and bounded next milestone

Suggested sourcing amendment, **only if adopted by the owner**:

> Andrix's Android/Pixel platform follows an explicitly pinned public GrapheneOS
> release and its reviewed Pixel support inputs. Android platform components stay
> Bionic and retain Android's kernel/identity/service authority. Andrix maintains a
> small attributable downstream layer for owner computing, network/release policy
> and independently verified fixes.

The rest of the accepted owner/environment architecture is not replaced by this
paragraph. A glibc ABI decision and GUI implementation remain separate.

If approved, run one bounded isolated migration trial:

1. Pin and authenticate the public source manifest and device/tool/kernel inputs;
   keep the existing AOSP checkout intact. Resolve vendor-input permissions before
   downloads/extraction and inventory generated outputs.
2. Build an attributable baseline and an Andrix-minimal variant with the signed
   `/usr` proof payload, deliberate product/app composition and safe update/network
   configuration. No new owner userland or GUI stack yet.
3. Re-run exact artifact/APEX/SELinux/app-boundary/network oracles on the appropriate
   ARM64 test target. Record missing kernel capabilities honestly. Qualify the
   signed/recoverable caiman product before proposing the first phone flash.
4. Make the first owner spike small: CE home, one bounded identity, terminal/PTYS,
   native compile/execute and same-owner child debugging. Keep ordinary-app negative
   controls. Test lifecycle and capability crossings before adding general packages.

**Exit criterion:** maintained Pixel build inputs plus a small, reviewable Andrix
layer, with no need to weaken ordinary-app isolation globally. If the owner spike
requires pervasive exceptions or a second broad platform fork, revisit the design
before committing to support it. Otherwise proceed with the GrapheneOS-derived
base and invest next in useful owner workflows, not reimplementing Pixel support.

## Source index

- [Pinned public manifest](https://raw.githubusercontent.com/GrapheneOS/platform_manifest/84536744f0c06cccbcfa2110e9c937671ddc3278/default.xml).
- Frameworks/base `aab06a8bd44c4c2b58eeec780fde83baa9d43a40`:
  [SELinuxFlags](https://raw.githubusercontent.com/GrapheneOS/platform_frameworks_base/aab06a8bd44c4c2b58eeec780fde83baa9d43a40/core/java/com/android/internal/os/SELinuxFlags.java),
  [app controls](https://github.com/GrapheneOS/platform_frameworks_base/tree/aab06a8bd44c4c2b58eeec780fde83baa9d43a40/core/java/android/ext/settings/app),
  [spawning](https://raw.githubusercontent.com/GrapheneOS/platform_frameworks_base/aab06a8bd44c4c2b58eeec780fde83baa9d43a40/core/jni/com_android_internal_os_Zygote.cpp),
  [RKP setting](https://raw.githubusercontent.com/GrapheneOS/platform_frameworks_base/aab06a8bd44c4c2b58eeec780fde83baa9d43a40/core/java/android/ext/settings/RemoteKeyProvisioningSettings.java).
- System/sepolicy `87a06ed71fd67cff9f77feaa9ae3504edb5d0972`:
  [app neverallows](https://raw.githubusercontent.com/GrapheneOS/platform_system_sepolicy/87a06ed71fd67cff9f77feaa9ae3504edb5d0972/private/app_neverallows.te).
- Bionic `b95b08888b9eb6465c21d5840cce59dc463bfdef`:
  [allocator dispatch](https://raw.githubusercontent.com/GrapheneOS/platform_bionic/b95b08888b9eb6465c21d5840cce59dc463bfdef/libc/bionic/malloc_common.cpp).
- [Pinned hardened_malloc documentation](https://raw.githubusercontent.com/GrapheneOS/hardened_malloc/714abf5a47258090016984e43c7bfbccdeb99fc7/README.md).
- [Pinned Updater configuration](https://raw.githubusercontent.com/GrapheneOS/platform_packages_apps_Updater/d7e29f110890de68b63bb8c256b4d249a2d29cf9/res/values/config.xml)
  and [AppStore import](https://raw.githubusercontent.com/GrapheneOS/platform_external_AppStore/5f32bce36bb1e38c037b10dfce93ec86d2e7d6eb/Android.bp).
- Official [build](https://grapheneos.org/build), [features](https://grapheneos.org/features)
  and [usage](https://grapheneos.org/usage) documentation. These live documents are
  explanatory sources, not replacements for the pinned implementation or runtime evidence.
