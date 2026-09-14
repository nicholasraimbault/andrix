# Native owner work in Android's lifecycle

**Status:** the platform service and native dependency were exercised in bounded
emulator checks. The later [Keep milestone](2026-09-14-keep.md) adds explicit retained
work. Independent live key-withdrawal and delayed-reply controls remain separate.

## Refined contract

Reuse Android's user/storage lifecycle, SystemService, Binder and init. The adapter
owns no keys, packages or owner files. User state, CE access observations, Keep consent
and foreground terminal access remain separate facts.

Android key withdrawal is asynchronous and may encounter busy files. Pre-request
revocation is event ordering, not a synchronous cleanup acknowledgement. Do not delay
or weaken key locking to satisfy an invented stronger barrier.

## CE observation and provenance

The guarded framework adaptation observes key create/unlock/restore, lock/destroy,
CE-directory destruction, backend replacement/death and reset. Keep upstream cache
semantics intact; use independent epochs, revocation accounting and operation tokens
for authority.

Two corrected races are important beyond their original tests:

- **Reset provenance:** a stale append to Android's cache must not become fresh key
  authority during a later reset. Revalidation requires previously verified state.
- **Backend publication:** install tracker identity before exposing a new vold
  binding, with death rechecking, so a revocation cannot bypass that identity fence.

Do not hold storage/lifecycle locks across Binder calls or process cleanup. Committed
Android user-stopping callbacks are distinct from earlier abortable transitions.

## Native observation

Bind one native daemon lifetime to one platform Binder instance and epoch. Death,
unavailability, replacement or an expired issued-query deadline ends the old workload.
Delayed replies cannot buy a new lease. The foreground/unlocked terminal lease remains
a separate gate; Keep never grants locked output or input.

## Observed image and runtime result

Bounded checks exercised platform startup/admission, normal unlock/relock, plain-work
cleanup, owner programming, ordinary-app negatives and reboot. The Keep follow-up
also exercised actual platform-process death and fresh recovery. These do not prove
all independent CE eviction, storage-backend failure, hung query, suspend or pressure
cases. No restart permission denial was treated as a successful failure test.

See [integration instructions](../owner/platform/README.md),
[guarded framework adaptation](../patches/grapheneos-2026081300/README.md) and
[lab fault-control scope](2026-09-14-lab-lifecycle-faults.md).
