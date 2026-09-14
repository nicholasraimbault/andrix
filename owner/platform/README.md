# Android-owned lifecycle integration candidate

See the [initial lifecycle baseline](../../plans/2026-09-13-android-lifecycle.md#observed-image-and-runtime-result)
and subsequent [opt-in Keep result](../../plans/2026-09-14-keep.md#observed-opt-in-keep-result).
Image `8a9a2ab` additionally exercised notification-backed kept work/return/Stop and
actual watchdog platform loss. Plain work remains Console-bound. Keep is off by
default; independent live key-loss and broader release behavior remain unqualified.
No ordinary APK receives user/storage management permissions.

The product flag `ANDRIX_OWNER_LIFECYCLE=true` requires `ANDRIX_OWNER_SESSION=true`.
It selects the system_server adapter jar/overlay, native observer and dedicated
policy. Android user lifecycle callbacks and init's named service controls remain
the machinery; the adapter owns no keys, packages, PTYs or owner files.

The source-only CE observation API is prepared by:

```
python3 scripts/proof/android_lifecycle.py --source-root "$ANDROID_ROOT" \
  --action apply --evidence "$NEW_EVIDENCE/framework-apply.json"
```

The guard accepts only the pinned framework HEAD, exact two-file adaptation and
one added helper. It rejects other source changes and validates the scratch-patched
bytes plus the exact host-tested method fragment. `check` identifies upstream,
adapted or interrupted partial state; a build must require the complete adapted
state. `revert` restores only those inspected bytes and removes only the exact new
helper. Never append receipts to an old sealed evidence set.

The internal framework hook is present in an adapted source checkout even when the
Andrix product flag is off, but no Andrix listener, native lifetime dependency or
control-policy grant is installed by that flag-off product. The original small
APEX must remain independently buildable and byte-reproducible.

## Protocol boundary

`andrix.owner.lifecycle.snapshot()` returns platform instance/generation/availability
and the current Keep registration identifiers. With the separate Keep flag, `keepWork`
can establish one notification-backed grant for an authenticated native work Binder;
it grants no terminal access or key management. Dedicated discovery, UID7500 checking
and the native worker Binder
filter separate the coordinator from both APKs and owner-controlled workers. PID
alone is not an identity. The native observer holds one live platform Binder for
its entire daemon lifetime; replacement, death, unavailability or expired observation
ends that group. No new platform instance is adopted into an existing native session.

Snapshot availability combines Android's user state with operation-fenced CE access
metadata. It is not proof of owner-home preparation, physical erasure, or completed
process cleanup. Readiness never bypasses the coordinator's existing home/admission
checks or the separate foreground/unlocked UI lease.

Global lifecycle commands to init run on a distinct coalesced handler. Notification
Stop instead targets the process-bound `IKeptWork` Binder so it cannot restart a
replacement by a reused service name. No callback waits for native cleanup or
changes Android's key-locking result. In particular, pre-request event
recording is not a synchronous pre-eviction completion guarantee.

## Host checks

The tracker tests exercise operation/revocation/backend fencing and listener
ordering. Reset revalidation requires previously verified availability: raw cache
entries, including those appended by stale replies, cannot bootstrap authority.
Tracker identity is installed before the vold binder is published. Revocations are
counted even for a null or stale captured binder, and connect/death do not drop
in-flight counts.
The adapted framework-method fixture includes connection, locking, restoration and
reset, retains upstream copyright, and is byte-checked by the source guard. It runs
with explicit host Binder/vold facades. Its stale-restore → lock → delayed
cache append → reset regression rejects the original `8986260` implementation.
The native pump tests include both flag-off and flag-on branches with a host
observation stub. None of those facades supplies Android runtime or identity proof.

Android compilation, image checks and bounded controls are recorded for `8b39806`
and opt-in `8a9a2ab`. The latter exercised actual system_server watchdog death with
Console absent and fresh recovery, without altering Android's timeout/permissions.
The earlier denied restart and too-short watchdog attempt remain failures. Direct
live CE-key eviction, hung snapshot RPCs and broader suspend/release controls remain
open; the tested opt-in mode is not unconditional production promotion.
