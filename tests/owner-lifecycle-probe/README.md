# Ordinary Android lifecycle witness probe

This optional test-only APK has **no native owner-session authority**. It does not
find or call `andrixd`, read owner home, start owner jobs, or change owner policy.
It is not a product package. Build `AndrixLifecycleProbe`, verify its APK identity,
then install it normally with the explicit test-APK flag.

The visible Activity requests Android notification permission, then starts a finite
foreground service in `:witness` only after another explicit Start action. The
service is non-exported and its Binder snapshot method also checks the same APK UID.
It observes public same-user running/unlocked state without MANAGE_USERS or
cross-user permissions. Keyguard and display state are diagnostic fields, not job
retention criteria. The service expires after 15 minutes or unusable observations,
uses `START_NOT_STICKY`, and has no boot receiver. UI binding does not auto-create it.

Manual/ordinary-shell observation sequence:

1. Open the Activity and grant notifications through normal Android UI. Start the
   monitor, then record actual UI/service PID, UID, epoch, advancing sample count,
   foreground notification and service metadata.
2. Use **Close this UI process**. That action signals only the Activity's own process.
   Check that the separate foreground witness remains live. Reopen the Activity and
   verify the same witness PID/epoch with advancing samples, not merely a new service.
3. Relock/unlock normally. Distinguish keyguard lock from the separately observed
   running/unlocked state. No claim about CE-key eviction follows from screen relock.
4. Stop the monitor explicitly and check cleanup. Separately test normal package
   force-stop and reboot: no automatic foreground service should be started afterward.
   Uninstall the test APK normally when finished.

A sample is usable only when all queries succeeded, both running observations and
unlocked are true, and the query was timely. A snapshot separately reports freshness.
Two/three sequential queries are not an atomic user-lifecycle transaction and cannot
prove that every short intervening transition was observed. A future native authority
must address monitor death, stale state, user-stop and key-eviction independently.

The [bounded Android trial](../../plans/2026-09-12-owner-lifecycle.md#witness-role-and-limits)
now records those controls, including same-witness return, relock, notification Stop
and 900.094-second automatic expiry. An explicit Stop can leave an Android-cached
process even though its service/foreground state is gone; process presence alone is
not a service-liveness or authority test. An unstarted service record from binding
also need not mean a witness process exists.

This remains groundwork, not qualification of retained owner jobs, terminal
restoration, production persistent services, user-stop/key-eviction/suspend behavior,
SSH or supported-phone operation.
