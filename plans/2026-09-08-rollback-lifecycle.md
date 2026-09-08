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

## Source defects and correction under qualification

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

The221 host tests pass, including extracted Java bodies with explicit mocked
Android surroundings and real host-file checked-commit trials. They cover injected
sync/close/rename errors, metadata-transition rollback, cause-list aliasing,
discarded instances, correct session matching, staged/non-staged getter contracts
and reconciliation states. They are not Android storage-fault, power-cut or image
execution evidence. Compiler/image and corrected runtime verification follow.

Forward staged consumers' **new**, separately installed library is a distinct
pending-install dependency, not an old-consumer rollback reference. Its unused
window must not be hidden by broadening rollback metadata to arbitrary future
packages. That boundary, concurrent owner package mutations, real Chromium data
migration, native ARM/KVM and full no-Google/security-consumer qualification remain
separate gates until demonstrated.
