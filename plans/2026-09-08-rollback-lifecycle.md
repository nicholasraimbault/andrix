# Rollback expiry, staged lifecycle and checked metadata commits

Continuation of [retention/Watchdog qualification](2026-09-07-rollback-retention.md).
Vanadium remains selected; this is not another provider-selection experiment or
production signing/update-policy decision.

## Frozen f5ff864 baseline observations

A fresh connected ARM64/TCG guest used the frozen positive image, not mutable OUT.
B/C and the additional D797708734/Config209 are manifest-only test generations:
original DEX/native/config payloads and resource semantics remain unchanged. D's
signatures, static-library relationship, ARM64 packaging and independent AAPT
roundtrip were verified; this is not a genuine Chromium upgrade.

- **Available expiry release passed.** Normal B then C consumer updates created
  C→B. Unused B deletion hit the rollback guard. Existing shell
  `TEST_MANAGE_ROLLBACKS` invoked the exact pinned Binder expiry API, removing that
  record with reason `Expired by API`; unused B then uninstalled normally.
  Reinstalling identical signed B and repeating the disclosed aggressive prune
  control removed it without changing C. No forced consumer downgrade.
- **Ready staged upgrade abandonment passed.** C→D became READY with C still
  active and its dependency retained. Normal owner session abandonment removed
  the enabling rollback; Android reboot kept C. This is deliberate cancellation,
  not a simulated power cut.
- **Staged update and rollback passed.** A subsequent C→D staged update applied D
  after reboot and made D→C available. Normal staged rollback kept D active and C
  protected while ready, then restored exact C/208 after another Android reboot.
  A default dumpsys observation timed out; a separate bounded 30-second observer
  confirmed the committed record's pin release. The failed observer was retained.
- **In-flight expiry defect reproduced.** A later ready D→C restore could be
  expired through the existing test API. Its required unused C library could then
  be removed while the staged install remained READY and D stayed active. This
  defeats a full in-flight-retention claim; no successful subsequent apply was
  invented.

A direct attempt to abandon the system-created rollback session from shell was
rejected by normal session ownership. No root, identity adoption or permission
bypass followed. It is not a successful rollback-cancellation test.

The session-list observer initially assumed exit0. Exact r1's successful
`runListStagedSessions` returns1 (errors return-1); the repaired observer checks
that status plus the exact ready parent ID. A second record observer was corrected
to distinguish a prior completed D→C from the new restoring record. Neither
correction changed Android state or relabelled the original failure.

Fresh security snapshots were explicitly fetched before connected work; old
snapshots were not retimestamped. Multiple HTTP Cache-Control header fields caused
the first host observer to fail; the subsequent fetch preserved all fields and
honored their combined freshness bound. Original CT signatures/data and independent
format freshness checks remain unchanged.

## Corrected runtime result — bounded pass

Final producer `d2ffbd8` built successfully in 845.003 seconds, completing
2026-09-08T05:45:34Z. The preceding `4699fcc` build took 5,033.178 seconds.
Both completed images and matching host packages were frozen and rehashed;
extraction confirmed the original signed WebView/Library/Config APKs and `/usr`
APEX, plus compiled correction identifiers. An interrupted first freeze preserved
its partial archive before verified resumption; no partial image was launched.

A fresh final ARM64/TCG guest demonstrated:

- **Typed in-flight expiry refusal:** Binder returned `EX_ILLEGAL_STATE` (`-5`)
  and the exact “Rollback restore is still in progress” message. The staged
  restore stayed READY, the record stayed committed/restoring and normal removal
  of required B remained denied. The same checks passed after explicit metadata
  reload through the existing test API.
- **Staged restore and release:** normal Android reboot applied the recorded
  C→B commit, restoring exact B/207 and trusted Config initialization. Persisted
  completion released its pin. A later normal forward C update then allowed
  unused B removal.
- **Available expiry remains allowed:** a forward D update made D→C available;
  the same caller/API expired it successfully and unused C could be removed.
  Final disposable state was D/209 with libraries A/D, not a promoted release.
- **Ordinary WebView:** normal local-network ALLOW, JS DOM42/HTTPS204,
  hostname-only TLS cancellation and uninstall passed at the declared D version.
  The credential-free guest's normal `wm dismiss-keyguard` surfaced the dialog;
  no credential, lock-policy or permission-grant bypass was used. Safe Browsing
  remains false. Exact original hello, read-only `/usr`, Android `/etc`, sole
  ARM64 ABI and enforcing SELinux were reobserved.

The intermediate `4699fcc` image also passed actual non-staged restoration and
state/reload/reboot/release checks, but its malformed refusal RPC remained a FAIL.
The final run specifically distinguishes a correct typed refusal from either a
successful expiry or an unusable Binder reply.

Final capture: **87,707 packets, zero kernel drops**, from
2026-09-08T05:47:21.831999Z through 06:32:01.144178Z. Guest destinations were the
owned fixture, public CT delivery and local multicast; namespace IPv6 was local
only. No unparsed traffic or Google guest destination was observed. This is a
measured connected workload, not universal no-Google/security-consumer proof.
The baseline and intermediate captures contained 142,853 and 91,886 packets,
respectively, both with zero drops; the baseline ordinary probe separately failed
its 180-second permission deadline and was not relabelled as HTTPS success.

All three VMs and service namespaces stopped with exit 0; the heavy lease was
released. Private evidence `rollback-lifecycle-20260908T010807Z` seals 8,180 regular
files; private artifacts, captures, credentials and signing keys are not published.
Real Android storage-fault/power-cut behavior, parent-directory durability,
system-owned rollback cancellation, ambiguous concurrent owner changes and the
forward-new-library window remain explicit limits, not quietly closed gates.

## Source defects and correction

Exact r1 `AtomicFile.finishWrite` logs sync/close/rename errors and returns void.
The earlier store boolean therefore only detected exceptions from earlier steps,
not every atomic commit failure. Its broad fail-closed write claim was too strong.
Also, staged READY is not APPLIED: deleting backups on that result prevents retry;
boot reconciliation must use the downgrade's committed session ID, not the upgrade
which originally enabled rollback.

The current eighteen-file/nine-project adaptation adds or corrects:

- A hidden checked `AtomicFile.finishWriteOrThrow` for sync, close, legacy-backup
  recovery and replacement errors; the old public API remains unchanged. The
  existing `.new`/`.bak` layout is preserved. No parent-directory sync or universal
  power-loss durability claim is added.
- Persisted COMMITTED/in-progress/session-ID/cause metadata before installer
  submission. Failed transitions restore prior in-memory state and do not publish
  a pin release. Ambiguous submission failure remains pinned for reconciliation.
- Staged READY retains backup APKs. Confirmed apply persists completion before
  deleting backups. Failed/abandoned attempts with usable backups can return to
  AVAILABLE without resetting their original lifetime.
- Committed-session reconciliation on boot, terminal callback and bounded worker
  maintenance. Staged-only SessionInfo getters are never called on non-staged
  sessions. Missing-session package versions are checked; ambiguous generations
  or missing backups stay explicitly unresolved, not falsely available/successful.
- Restore records are not expired while in flight; the test expiry API refuses
  them. Completed commits still expire. Commit-session matching is limited to
  restoring records and never changes the original enable-session lookup.
- Discarded instances cannot overwrite reloaded metadata through a stale result
  closure. Caller results report a superseded observer rather than invent success.

Signature verification, PackageInstaller authority, Android identities, SELinux,
TLS/CT, ARM64/Bionic and the read-only `/usr` boundary are unchanged. An independent
writer lacked access to the source snapshot and produced no changes/tests; primary
implemented and tested the correction. Independent read-only reviews were advisory.

## Verification boundaries

The 221 host tests pass, including extracted Java bodies with explicit mocked
Android surroundings and real host-file checked-commit trials. They cover injected
sync/close/rename errors, metadata-transition rollback, cause-list aliasing,
discarded instances, correct session matching, staged/non-staged getter contracts
and reconciliation states. They are not Android storage-fault, power-cut or image
execution evidence. Producer `4699fcc` subsequently built and its frozen images
retained the original APKs/APEX and compiled correction identifiers. The live
non-staged restore passed. Its in-flight expiry guard held the dependency, but
throwing from the worker produced an unsupported RuntimeException wrapper at
Binder: `Parcel(Error: ... "Not a data message")`. The original RPC/test failure is
retained. A narrow follow-up returns a boolean from the worker and throws the
supported IllegalStateException on the Binder thread. A changed-function test
reproduces awaitResult's wrapping behavior; state protection and RPC correctness
are not conflated. The final image/runtime result above verified the actual typed
response separately from those host tests.

Forward staged consumers' **new**, separately installed library is a distinct
pending-install dependency, not an old-consumer rollback reference. Its unused
window must not be hidden by broadening rollback metadata to arbitrary future
packages. That boundary, concurrent owner package mutations, real Chromium data
migration, native ARM/KVM and full no-Google/security-consumer qualification remain
separate gates until demonstrated.
