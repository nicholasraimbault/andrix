# Uncertain replies and retained work controls

Status: the listed finite Android controls pass against service implementation `4829af5`
with the ordinary test client added at `acdba46`. The service, image policy and default
Console path were unchanged. This extends the
[service runtime result](2026-09-20-work-service-runtime.md), not every submission failure
or recovery case.

## Method

The [transport probe](../tests/owner-work-service/transport_probe.cpp) is an ordinary owner
program, not a privileged bootstrap or a new service operation. It uses the existing
peer authorization, packet framing, operation codec and sealed description libraries.
Those library inputs matched the manager image's source. The owner SDK compiled the
probe inside a fresh offline Android fixture from a checked source archive.

The probe starts with a known request stream and reserved work reference. A parent retains
that identity and an independently bound control. A forked submitter uses the inherited
socket under the same owner principal, sends one operation, and never receives its reply.
After notification that the packet send completed, the parent kills the submitter through
its retained pidfd and reaps it. This deliberately leaves the operation outcome to be
reconciled, rather than treating successful send or client disappearance as acceptance.

This exercises permitted same principal descriptor sharing. It does not make the sender's
PID an authentication credential. Kernel credentials, the actual typed endpoint and ongoing
MAC controls remain required.

## Observed controls

### Unread preparation and Start replies

A Prepare request was sent without its reply being received. No Start was sent for that
reservation. After the submitter died, the exact record remained unstarted and closed with
Manager cancellation. Input cancellation reported `ECANCELED`, and the actual pipe reached
EOF while the result/control remained retained. Reconnection with the original stream and
sequence found the original record; attempting Start did not create replacement work.

In a separate case, a Start reply was not received before the submitter was killed. The
accepted work continued. Reconnection with the original still open stream, sequence and
input identity found that same accepted work. Twenty identical Start retries while live,
and one after Stop, returned Existing. The observed initial PID/scope stayed the same, and
exactly one payload marker preceded pipe EOF. There was no extra retained registration
writer after the lost reply.

These cases establish unread operation replies, not whether the server's send succeeded
before the peer disappeared. They are finite controls, not exhaustive acceptance races.

### Retained controls and bounded identity lifetime

The probe stopped work A, waited for complete scope and runtime retirement, then forgot it
while retaining its bound control socket. Management conversations were separately retired
by half close and observed server EOF. Concurrent Hello acknowledgements on both selected
management workers excluded earlier management conversations as an alternative record pin.

A replacement work B remained live while the old bound control was inspected and stopped.
Trying to bind or Stop B through that old control returned Foreign. Reusing A's old input
identity for B also failed before B's correct Start.

With the forgotten record still pinned by its control, the selected four record capacity
was reached. Another reservation returned Capacity. Closing the old control allowed a
reservation under a new serial; a fresh lookup of A was then stale. The fixed capacities
and worker count are test configuration, not permanent product quotas.

### Manager replacement and raw stale requests

The owner client retained another old control across manager shutdown and replacement.
Independent kernel samples showed the same client PID, start time and separate caller
cgroup before and after that replacement. Android retired the old service environment
before the new one activated.

The old retained socket failed with `EPIPE`; it did not become a connection to the new
service. After authenticating the fresh service, the probe sent old namespace metadata in
actual List, Bind and Stop frames. The new service returned Stale. This differs from the
earlier CLI check that refused an old environment reference before sending it. A current
work item remained live and unstopped after the stale Stop, then completed only after its
own Stop and retirement sequence.

Final discovery and the independently observed owned hierarchy were empty. The fixture
shut down with matched frozen inputs and unchanged boot, framework and platform bookends.

## Evidence and limits

434 host checks passed, including the new client's codec/link check. AddressSanitizer and
UndefinedBehaviorSanitizer also passed its codec self test. These are not successful Android
peer authorization tests. The actual Android client checked authenticated replies and
kernel/descriptor behavior; primary assessment checked those assertion paths, source and
output correspondence, independent process samples, stopped init logs and resource/input
closure. It is not a complete independent wire transcript or exhaustive protocol fuzzing.

The first fresh fixture reached its compilation observer deadline before any transport
exercise. Later compiler activity was not promoted to success. That incomplete result stays
recorded. A fresh fixture used a measured, longer but bounded compilation observation budget
within the existing service/VM bounds. Resource, authority, policy and timeout ownership
rules were not changed, and no active input was edited.

The tested recovery assumes that another participant retains the original identities.
It does not qualify loss of OpenStream/Reserve replies, loss of every local identity, cold
client recovery, durable receipts, forced numeric PID reuse or all stalled kernel paths.
Streams still require explicit closure. If an unused stream's reply and identity are lost,
the current interface has no stream discovery operation to resolve that case. The CLI also
closes its stream early and publishes a Start reference only after acknowledgement. Those
remaining client/recovery issues are not solved by this richer protocol exercise.

Next address initial identity recovery and stream lifetime, then actual Console/isolated
callers, additional descriptors and complete terminal behavior. Pending admission/entry
across CE recovery, broader failure/pressure/suspend behavior and physical phones retain
separate gates. No persistent activity history or default Console migration is implied.
