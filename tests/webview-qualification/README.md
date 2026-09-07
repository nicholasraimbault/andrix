# Optional frozen-WebView qualification fixture

**Implementation, not a qualification result. Never product-install this APK.**
One `AndrixWebViewQualification` module, package
`dev.andrix.proof.webviewqualification`, public SDK/min/target **37**, no requested
permissions, shared UID, native code or third-party libraries. It neither changes
provider code/allowlists nor spoofs `com.android.vending`. No Android hidden API,
root, `run-as`, UiAutomation, adopted permissions, platform certificate, direct
private-file/preferences edits, component disable, or verification bypass.

## Pinned contract and build

The fixture includes the unchanged public Chromium152 AIDL, its typed adapter
and the exact upstream BSD license. The primary checked the actual source,
provider manifest, R8 mapping and compiled callback; no descriptor or transaction
number is guessed. The AIDL SHA-256 is
`881975244f5e77d7f3184484b78cd2f4c5cbe2931e69887c2172e16c68c66abc`.
`prepare_contract.py` is an explicit maintenance/import helper, not a build-time
download or a dependency on private operator files. The AIDL compiler determines
transaction order. Review any changed upstream contract before refreshing it.

Before compile/run, confirm against the frozen snapshots and actual DEX:

- Imported contract and BSD terms; public actions cursor is one string column,
  one action per row. Getter is a nonnegative timestamp. Alias/component names
  and public binding/query access below match the actual provider manifest.
- `WV.xr.a` is static `byte[]` containing the config certificate SHA-256;
  `WV.op1.b` is static `Future`, `WV.op1.c` static `WV.mp1`, and `WV.mp1.b` an
  instance `long`. The public WebView loader filters non-support-library names. The fixture loads
  only the permitted `SupportLibReflectionUtil` glue entry, then uses public
  `Class.getClassLoader()` to obtain its actual defining provider loader. No
  private Android/delegate field is read and no duplicate DEX loader is created.
- Actual job ID is **83**, not a source-only/pruned scheduling constant. Confirm
  the real `onStartJob` only cancels 83 and returns false. No private method or
  pruned `scheduleJob`/VisibleForTesting hook is invoked by this fixture.
- The provider's own manifest/UID has the public `RECEIVE_BOOT_COMPLETED`
  permission needed for a persisted job, and its JobService requires
  `android.permission.BIND_JOB_SERVICE`. The test APK requests neither. Confirm
  that the public `NetworkRequest` shape and four extras survive JobStore
  restoration; only the latency is deliberately allowed to rebase.

Then, in the exact `android-17.0.0_r1` API-37 public-stub lunch environment:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tests/webview-qualification/host-tests -v
m AndrixWebViewQualification
```

Source tests are limited regressions, not evidence that Android APIs, Binder or
reflection work. The initial implementation worker ran no tests; primary build,
signing and runtime results are recorded separately. Compile against the actual
r1 public stubs (`sdk_version: "current"`, API37), then inspect and execute the
exact signed APK before claiming any mode passed.

Initial build certificate is existing `:dev.andrix.usr.certificate`. The operator
externally re-signs with the **existing disposable provider signer**, never the
platform key; this repository does not handle/generate signing keys. Inspect the
final APK's signer, manifest, SDKs, two instrumentation entries, non-exported
Activity, absence of permissions/shared UID/native/extra payloads and lack of
product inclusion. Freeze hashes and install only the reviewed disposable APK
on the authorized fixture, freshly, normally under `/data/app` (`-t`, not `-g`).
No replacement of the provider/config APK or install orchestration is supplied.

## Authority and mandatory guards

Every invocation requires `mode` and an exact `expected_fingerprint`. API must
be **37**, and the already-selected provider must be
`dev.andrix.experiment.webview`. Before a bind, job operation, WebView creation or
reflection, public PackageManager observations, actual target/process UID and
provider pins must match. Public signature comparisons must also exclude the
platform signer for both APKs:

- Current provider signer SHA-256:
  `6c292164d3710a4fd44b91d90fd3a2c894fe4c6945dd41f52493ffb19389b5b3`.
- Exact `classes.dex` SHA-256:
  `1a2dcd3b0af00bbb4c52ba215245dfc7c86011b8a4b2318d445d5db2ad7cf755`.
  Read through `publicSourceDir` ZIP, requiring one DEX entry and bounded size.
  Versions-only rehearsal containers may differ; the DEX may not.

Public package visibility queries name only the provider and
`dev.andrix.experiment.webviewconfig`. Selection/source is rechecked around
WebView initialization. No provider switch occurs. The host must prevent
concurrent package updates, invocations and other writers throughout a run.

- **`.SelfInstrumentation`** uses its **own UID**, distinct from the provider.
  `different-uid` works even when both APKs have the same disposable certificate.
  It is **not a different-signer ordinary-app proof**. Self config modes can also
  use the initial non-platform test signer.
- **`.ProviderInstrumentation`** uses `getTargetContext()` and the **real provider
  UID**. Android must admit same-signer instrumentation, and the fixture checks
  the signer relationship and actual UID again. This is deliberate white-box
  provider authority, **not ordinary-app authority**. Cross-UID JobScheduler
  operations cannot substitute for it. No mocked Context/PackageManager is used.

## Modes and retained state

| Entry | Mode | Required additional arguments / assertion |
| --- | --- | --- |
| Self | `different-uid` | Starts clear. Successful bind and timestamp getter, public actions/alias controls; **only the actual AIDL setter** throwing `SecurityException` satisfies denial. Requests an empty list, so unexpected acceptance cannot introduce fast state; acceptance still FAILS. Rechecks clear public state. |
| Provider | `fast-on` | Starts clear, no job 83. Sets only `[fast_variations_seed]` through Binder. Requires that exact action, timestamp > 0, alias explicitly ENABLED/effectively enabled, job 83 absent. Leaves actions intentionally persistent, `cleanup_required: true`. |
| Provider | `fast-off` | Only empty/known fast actions accepted. Clears through Binder; requires empty actions, timestamp 0, alias DEFAULT, job 83 absent. Never calls scheduler cancellation directly in this mode. |
| Provider | `job-stage` | Explicit `marker`. Requires no existing job 83 (including old test jobs). Schedules a synthetic persisted job at real provider UID, minimum latency **one day**, network ANY. Leaves it for host reboot/callback testing; cleanup required. |
| Provider | `job-present` | Same explicit `marker`. Requires job 83, exact service, persisted/non-periodic, network ANY and exact four extras. Records latency but permits JobStore to rebase it across reboot. Leaves state. |
| Provider | `job-absent` | Same explicit `marker` for evidence correlation; bounded wait for job 83 to become absent, accepting only this exact marked job while waiting. **Absence alone does not prove a callback**: host must retain prior stage/present, reboot and actual normal callback invocation evidence. |
| Provider | `cleanup` | Normal fast-off assertions; optional `marker` first cancels job 83 **only after exact ownership verification**. Wrong marker/component/extras FAIL without cancellation or action writes. Without marker, only the normal Binder fast-off path can remove a job. |
| Self | `config-trusted` | Explicit nonnegative decimal `expected_config_version`. Initializes an actual WebView in the non-exported Activity, no page loads. Real `hasSigningCertificate(config, expected pin, CERT_INPUT_SHA256)` must be true; compiled pin bytes must equal the frozen signer digest above; parsed `WV.mp1.b` must equal the requested version and be nonnegative. Any present parser Future must complete without failure/cancellation. A cached parsed object with null Future is recorded as such, not an observed Future completion. |
| Self | `config-untrusted` | Run only on the clearly labelled **factory wrong-config-signature image**. Config package must exist; real pin check false. After actual WebView initialization, both parser Future and parsed object must be null. Absence of the package is not the signer negative. |

Marker syntax: 1..64 ASCII letters/digits/dots/underscores/hyphens, first character
alphanumeric. Job extras are exactly `RequestFastMode=true`,
`PeriodicFastMode=false`, `RequestCount=0`, and
`dev.andrix.proof.webviewqualification.marker=<marker>`. The service is
`org.chromium.android_webview.services.AwVariationsSeedFetcher`. A marker is a
fixture ownership convention, not authentication; use a fresh unique value and
exclusive host orchestration. No `cancelAll`, component disabling, forced private
callback invocation or provider-scheduling-hook call exists here.

SafeMode reads use the existing getter, public URI
`content://dev.andrix.experiment.webview.SafeModeContentProvider/safe-mode-actions`
and `org.chromium.android_webview.SafeModeState` alias. All action mutations use
`org.chromium.android_webview.services.SafeModeService` and its unchanged AIDL.
The service's existing same-UID-for-tests allowance is the intended authority.
Unknown pre-existing actions are preserved, not silently cleared. Errors attempt
to clear only this run's known fast state/verified marked job, using those same
APIs. Unexpected replacement jobs/actions are preserved with a cleanup failure.

Config reflection is narrowly **read-only third-party DEX field inspection** via
public `WebView.getWebViewClassLoader()`. `setAccessible(true)` permits reading
those Java fields; it does not alter their values. No private verifier invocation,
reflective write (including pin-array mutation), Android boot class inspection,
HTTPS load, JavaScript or ALN grant occurs. These checks do **not** prove JS/TLS,
all configuration policy, no-Google egress, Safe Browsing, or update safety. The
existing ordinary network probe and host captures remain separate.

## Example authorized invocations (not executed here)

Prepare unlocked user 0 and an exclusive authorized device lease. Never infer the
expected fingerprint or config version from the device under test. Use reviewed
host inputs and allow at least **1200 seconds per instrumentation command**.
Provider instrumentation can restart provider processes; do not overlap it with
ordinary embedding/callback tests. This is not a safe-install/reboot orchestrator.

```sh
: "${ANDROID_SERIAL:?explicit authorized device}"
: "${EXPECTED_FINGERPRINT:?reviewed image fingerprint}"
: "${EXPECTED_CONFIG_VERSION:?reviewed baseline config version}"
: "${MARKER:?fresh bounded test marker}"
SELF=dev.andrix.proof.webviewqualification/.SelfInstrumentation
PROVIDER=dev.andrix.proof.webviewqualification/.ProviderInstrumentation

adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e mode different-uid -e expected_fingerprint "$EXPECTED_FINGERPRINT" "$SELF"
adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e mode config-trusted -e expected_config_version "$EXPECTED_CONFIG_VERSION" \
  -e expected_fingerprint "$EXPECTED_FINGERPRINT" "$SELF"

adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e mode fast-on -e expected_fingerprint "$EXPECTED_FINGERPRINT" "$PROVIDER"
# Host now performs separately authorized ordinary embedding and/or reboot checks.
adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e mode fast-off -e expected_fingerprint "$EXPECTED_FINGERPRINT" "$PROVIDER"

adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e mode job-stage -e marker "$MARKER" \
  -e expected_fingerprint "$EXPECTED_FINGERPRINT" "$PROVIDER"
# Host separately reboots, waits for boot/unlock and rechecks exact identity.
adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e mode job-present -e marker "$MARKER" \
  -e expected_fingerprint "$EXPECTED_FINGERPRINT" "$PROVIDER"
# Normal Android shell jobscheduler command; retain output/logs. No root/adoption.
adb -s "$ANDROID_SERIAL" shell cmd jobscheduler run -f -u 0 \
  dev.andrix.experiment.webview 83
adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e mode job-absent -e marker "$MARKER" \
  -e expected_fingerprint "$EXPECTED_FINGERPRINT" "$PROVIDER"
adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e mode cleanup -e marker "$MARKER" \
  -e expected_fingerprint "$EXPECTED_FINGERPRINT" "$PROVIDER"
```

On the separately built, labelled factory wrong-signature config image, use its
explicit reviewed fingerprint with `-e mode config-untrusted` and `$SELF`.
Do not supply `expected_config_version` to that mode. Do not replace/patch a
running baseline config or relax the compiled pin to manufacture the negative.

## Results, bounds and cleanup

Each runner stage waits at most **180 seconds**, including synchronous Binder,
PackageManager, ZIP reads and reflection inside the serialized worker. Main-thread
Activity launch, bind/unbind and WebView lifecycle are asynchronous; there is no
`runOnMainSync`/`startActivitySync` or UI-thread wait. Cleanup waits for actual
Activity `onDestroy`, after WebView detach/destroy, and for main-thread unbind.
Errors, timeouts, Future failures and cleanup failures remain in the report.

A timeout cannot forcibly repair a hung Binder transaction or main thread.
Cleanup is queued on the **same worker**, not a competing state writer; queued
work may also time out. No completion is presumed. Missing cleanup, app death or
missing/malformed/truncated results require host reconciliation, not PASS.
The host must exclude races between ownership checks and cancellation; Android
has no compare-and-cancel JobScheduler primitive. Provider private state is never
used as the fixture's bookkeeping store.

The result bundle contains `webview_qualification` (schema-1 JSON with `status`,
mode/authority/UID, `cleanup_required`, ordered timed observations and full caught
exception stacks) and `webview_qualification_status`. Only **PASS plus final code
-1** (`Activity.RESULT_OK`) and complete expected stage/cleanup evidence count;
FAIL returns **0**. Do not use adb exit status alone. Raw package sources/signers,
pin bytes, parser null/done/cancelled/version states, actions/timestamp/alias and
job/service/persistence/latency/extras are recorded where reached.

`cleanup_required` describes known/possibly written fixture provider state, not
proof that unknown foreign jobs/actions or a hung process are absent. Successful
fast-on and stage/present intentionally leave state for subsequent tests. End
with a passing provider `cleanup` (same marker if a job was staged), then recheck
identity and remove only the acknowledged disposable test package. **Uninstalling
the test APK does not clear provider state.** No provider `pm clear`, blind
uninstall, preference deletion, global job cancellation or signer change is a
cleanup substitute. Retain failures and host observations outside source.

The initial runtime config observer attempted WV.xr directly through the filtered
public loader and failed with ClassNotFoundException. That failure is preserved;
only the observer follows the source-confirmed glue-class loader path now.
