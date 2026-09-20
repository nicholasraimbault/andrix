# Initial request identity and stream lifetime

Status: implemented in the selected service candidate, with host component checks.
This extends the [known identity transport controls](2026-09-20-work-service-uncertain-replies.md).
The earlier Android image does not qualify these changes.

## Problem and boundary

The earlier client learned a stream ID from OpenStream, a work ID from Reserve, then
published a work reference only after Start acknowledgement. Losing an early reply could
leave the caller unable to name its reservation. Opened but unused streams were never
closed by connection cleanup. Enough abandoned OpenStream replies could therefore consume
all stream capacity without leaving work discoverable through List.

Recovery must not silently create another reservation or program. IDs are metadata in an
authenticated service namespace, not capabilities. Bounded volatile state cannot promise
durable receipts or recover intent after every copy of the request identity disappears.

## Provisional unused streams

The selected dispatcher tracks only streams opened by that management conversation.
When it ceases dispatch, it conditionally closes those streams that have never issued a
reservation. The registry tests and closes `high_water == 0` under the same mutex used by
Reserve to publish its sequence and issue an allocation ticket.

If Reserve wins that ordering, the stream is used and stays reconnectable until explicitly
closed. If conditional close wins, Reserve cannot issue a ticket. Capacity failure or an
invalid reservation does not turn an otherwise unused stream into a retained one. A close
does not reset the stream counter, release pending allocation ownership or Stop accepted
work. Other authenticated conversations may use the same issued stream subject to the
existing principal and endpoint rules.

This is an explicit change to the unreleased service contract: an empty stream is
provisional until a reservation is issued. Receiving its OpenStream reply alone does not
retain it across loss of its issuing conversation. Used request streams are still not
bound to a single connection. The registry's general OpenStream interface remains separate
from this dispatcher ownership helper.

## Lookup without submission

LookupRequest takes the original stream and sequence under the exact service incarnation.
It searches retained reservation records before considering the stream table. Therefore a
closed or recycled stream table slot does not hide a still retained allocation or work.
The lookup never issues an allocation ticket, reopens a stream, prepares inputs, Starts work
or adds the result to the querying conversation's cancellation set.

Its results distinguish:

- Existing, the exact retained work and current snapshot.
- Pending, the original allocation is still owned, even after stream closure requested
  its cancellation. A timeout or query does not consume that obligation.
- Closed, a retained failed allocation attempt and its error.
- Stale, the request was forgotten or overtaken, or the stream retired without a retained
  result. This does not prove that an earlier request never executed.
- NotFound, no retained attempt for that not yet issued sequence in a currently open
  stream. This is an observation, not a fence against a request arriving later.

The existing capture publication fence also applies to lookup. If Forget/Collect retires
canonical metadata during lookup, it is not recreated with fresh defaults.

## Native client behavior

The client attempts to print a request reference to stderr before Reserve:

```
andrix-work: request BOOT.ENVIRONMENT.MANAGER.STREAM.SEQUENCE
```

After a Reserve reply, it also prints the work reference before Prepare/Start:

```
andrix-work: reserved BOOT.ENVIRONMENT.MANAGER.WORK
```

These are volatile caller output, not a durable receipt or confirmed delivery to another
process. Closed, discarded, blocked or failed stderr cannot guarantee recovery. No history
file, raw arguments or environment data is written, and computation does not gain a
mandatory writable history store. The existing accepted `start` reference remains.

Two candidate commands use the request reference:

```
andrix-work request-info BOOT.ENVIRONMENT.MANAGER.STREAM.SEQUENCE
andrix-work stream-close BOOT.ENVIRONMENT.MANAGER.STREAM.SEQUENCE
```

`request-info` only observes. Its JSON includes a work reference when known, including an
allocation that is still pending and not yet bindable. Existing work snapshots and List
also expose the original request reference. The client never retries using a new key.

`stream-close` explicitly closes the **whole request stream**, not just the named sequence.
It prevents further reservation issuance and requests cancellation of pending allocations.
It neither Stops accepted work nor substitutes for work Stop. Retained request lookup
continues to work after that closure. Normal `run`/`start` still close their stream early;
the new lookup does not require reopening it.

## Verification and remaining gates

Host checks exercise 100 provisional stream closure/reuse cycles, 200 conditional close
versus Reserve races, retained pending allocation through stream closure/reuse, failure and
forgotten results, lookup without allocation or implicit input cancellation, exact input
metadata with real pipe EOF, nonwrapping stream exhaustion and reference/operation codecs.
The controlled allocator schedule also checks lookup racing Forget/Collect. Supplied
conversation termination in those component tests is not an actual Android socket loss.
Dispatcher nonadoption and CLI publication ordering also have source checks.

445 host tests passed in 214.533 s. AddressSanitizer, UndefinedBehaviorSanitizer and
ThreadSanitizer cover the recovery and capture binaries. A GCC syntax check failed on a Clang attribute in Android's libbase
header; the pinned Clang syntax check passed without suppressing that warning or changing
the header. This is not yet a complete Android manager/client compilation or runtime gate.

Next compile both Android selections and exercise actual lost OpenStream and Reserve
replies, query connection loss without cancellation, and the CLI recovery path. Those cases
must distinguish pending from final outcomes and retain the earlier accepted work/retry
and stale control behavior. All identity loss, optional durable recovery, further caller
and terminal integration, and CE/pressure/phone behavior remain separate work.
