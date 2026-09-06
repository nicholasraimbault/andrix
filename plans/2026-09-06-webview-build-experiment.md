# Isolated Vanadium WebView build experiment

**Authorized scope:** the owner approved one isolated WebView-only build
experiment following the [integration assessment](../docs/vanadium-assessment.md).
This is a narrow exception to the earlier reference-only rule, **not** permission
to replace Andrix's current provider, import GrapheneOS into Repo/product
inheritance, boot Android, rent a machine or publish a supported release.

## Inputs and outputs

- Vanadium: `fdcc1b50ce6fb34c87b2fb11978f9f3ce76fe226`.
- Chromium: `152.0.7977.84`, tag commit
  `4334922f44c77b1208072c4deac29db3af39bbea`.
- depot_tools: `81577f19a8497ba7e41afac322e8f03553a863ec`;
  automatic repository updates disabled.
- All upstream Vanadium primary/subproject patches remain the initial build
  baseline. Record their order/hashes and every derived-source change.
- Desired outputs: ARM64-only TrichromeWebView, TrichromeLibrary and VanadiumConfig.
  Do not build/install the standalone browser APK or a 32-bit secondary ABI.
- Experimental package identities: `dev.andrix.experiment.webview`,
  `dev.andrix.experiment.trichromelibrary`,
  `dev.andrix.experiment.webviewconfig`. Any unused browser package argument
  uses `dev.andrix.experiment.browser`, not an official upstream identity.
- A separate disposable APK signer may identify these experimental artifacts;
  it is not an official release-signing decision. Its private material stays
  outside Git/evidence/chat on the build host. Do not reuse, regenerate or move
  existing Android/APEX keys. Bind library/config public certificate pins to
  the actual experimental signer and verify all three APKs independently.

## Execution boundaries

Use a new source/output tree outside the AOSP checkout and the primary Andrix
worktree. Take the host's exclusive heavy-work lease for source sync/builds;
record disk/inode checks and bounded parallelism. Preserve failures before a
bounded repair. Do not force/reset an unexplained source state or advance tags.

Fetch the exact Chromium source and its pinned dependency/tool inputs. Do not
run unreviewed hooks implicitly. Stage and hash mutable filter-list inputs,
including source URLs and notices, before they become build inputs. A source
commit alone does not identify those lists or all tool artifacts. Source/tool
fetches from Google-hosted open-source infrastructure are recorded build supply,
not Android runtime traffic or a no-Google pass.

The first experiment establishes build feasibility and artifact identity; it
does **not** silently settle the assessment's network defaults, fast-seed,
Safe Browsing callback or update-policy questions. Keep upstream security
behavior for the build baseline, document it, and do not install it. Preserve
CFI/MTE/sandbox/TLS checks rather than disabling them to obtain a successful
compile. No remote execution, metrics opt-in or paid service is selected.

## Verification and promotion

A successful compiler exit is insufficient. Check APK signatures and signer
pins, package/SDK/version metadata, static-library dependencies, config inputs,
ARM64-only native contents, ELF alignment/linkage and exact artifact hashes.
Freeze the artifacts separately from the existing Andrix candidate. A failed
signing command must not be ignored.

Andrix's AOSP r1 image, `com.android.webview` 145 prebuilt, proof APEX and app
boundary remain unchanged. Provider registration, image integration, runtime
rendering/TLS/sandbox/network tests, update/rollback ownership and any production
use require later decisions and qualification. This experiment is not P3/P4/P5
clearance.
