# Captured service registration with LMKD

**Status:** optional candidate. At `5f9c893`, init and LMKD compiled and linked together,
the actual init parser cases passed, and the LMKD packing/descriptor send host test ran
from a frozen artifact. The first fresh Android trial at `40696f3` observed actual init
registration of the captured pair. A separate init readiness failure prevented its
memory reaper control. No memory kill, reconnect race or pressure result is claimed.

The pinned LMKD source selects both its pidfd and cgroup control from a registration
containing numeric PID/UID metadata. For services, process type skips application soft
limit policy; it does not change this resource lookup. A fresh delegated root therefore
has no matching UID/PID path. It could also encounter an unrelated leftover pathname.
Falling back to a pidfd kills only the initial process, not the whole delegated scope.

Changing the resource layout must not leave memory supervision guessing. The candidate
adds a complete registration operation from init containing:

- The original captured pidfd and recursive `cgroup.kill` descriptor.
- Declared UID and memory priority metadata.
- The immutable supervisor boot and service incarnation identity.

Only actual init PID/UID/GID and the connection's init SID may use this operation. The
receiver checks the descriptor kinds, target pidfd metadata and live state. It does not
reconstruct a privileged resource path from the PID. The existing reaper then uses the
captured group control, with its existing exact pidfd fallback, not a numeric signal.

Removal and repeated registration carry the same incarnation. A legacy PID request cannot
claim a live scoped record, including after disconnect. A positively exited old record
may yield its PID index to a different process. Repeated registration cannot retarget a
live incarnation to another resource. Received descriptors remain owned on all error paths.

Init retains its existing connection/retry and registration semantics, including recovery
registration of live services. Registration transport success is not a fabricated LMKD
acknowledgement. The old registration packet is now explicitly zero initialized so its
`for_lmkd_only` field cannot be indeterminate. No ordinary registration format or opcode
is renumbered. Unsupported scoped registration is refused, not downgraded to UID/PID
lookup. The selected debug memory test operation targets one exact registered service
and invokes the same reaper used for memory pressure; it is not a production control API.

## Alternatives and costs

- Keeping UID/PID lookup would discard the new resource identity guarantee.
- Disabling LMKD registration would weaken Android's memory supervision.
- Inferring a parent from task membership would assign policy from pathname conventions
  and would race placement/registration. It would not prove the aggregate boundary.
- Passing captured handles preserves the existing ownership model. It adds a small
  private protocol extension, descriptor validation and incarnation bookkeeping.

The new commands and handling are selected only with the delegated service proof. Normal
images use the unchanged sources. Existing clients continue to use the existing protocol.
No Andrix work identity, terminal state or CE admission policy belongs in LMKD.

The packing/send host test, compiled Android daemon/library/policy checks, a fresh actual
registration and memory reaper control with independent live scopes, reconnect/removal
races, and memory pressure qualification remain distinct gates. The last of these is
not replaced by the debug reaper control. More general callers or resource hierarchies
would require a new authority and compatibility review.
