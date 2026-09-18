# First finite Android delegated service result

Status: the listed generic service supervision controls passed in a fresh offline
Android emulator at `df1a4b8`, using the implementation at `b504a97`. This is not a
product release, a replacement owner work API or physical phone qualification.

## Goal and boundary

The accepted ownership direction is unchanged: Android supervises the owner environment,
Andrix manages work inside it, the kernel enforces containment, and Console is a client.
This vehicle tests the Android side before changing ordinary work or presentation.

A complete declared service profile receives a fresh captured cgroup root and a readiness
channel. A separate fixed cleanup worker operates outside init's main loop. LMKD receives
captured process and recursive group controls, not a reconstructed UID/PID path. Stop,
initial process exit/reap, subtree emptiness/removal, worker retirement and replacement
are distinct facts.

## What ran

401 host tests passed at the image source. The complete selected image and matching host
tools were built, inspected and frozen. Current normal module, policy and exclusion
checks passed separately, with their checked artifacts identical to the retained normal
image. No new complete normal image is claimed for this iteration.

The fresh enforcing Android trial completed these controls:

- Actual Bionic spawn behavior: a valid signal profile, refusal of an invalid profile
  that requests resetting uncatchable signals, then a valid profile again.
- Service activation after real worker initialization and bootstrap readiness. The
  bootstrap checked its actual credentials, capability sets, limits, resource identity
  and control membership. Writes to protected aggregate and ancestor migration controls
  failed with EACCES.
- Two held fixed descendants were released. They entered separate Unix sessions inside
  the delegated tree. After the initial service exited, they remained alive and made
  progress while the cleanup worker was stopped.
- Init processed an unrelated service Stop and Start during that pause. Starting a
  replacement of the same scoped declaration was refused before retirement.
- Resuming cleanup terminated the contained descendants, reclaimed the captured tree,
  retired the worker, and allowed a fresh empty service instance. One delegated child
  directory had deliberately been changed to mode zero. Retirement crossed the service
  UID to the platform cleanup UID without general DAC override.
- An old exact Stop reference did not stop the replacement. Actual worker death and reap
  allowed a replacement worker without replacing the active service process. Fresh
  useful work ran afterward.
- The selected LMKD test operation used the same captured resource reaper path as memory
  kills. It terminated the target service and descendants while the unrelated service
  remained live. Init cleaned that scope and restarted a new empty instance, not old jobs.
- Final exact Stop left both test services stopped and the owned instance hierarchy empty.

Independent process samples observed the stopped worker under its declared UID/GID and
SELinux role, with only CHOWN in effective/permitted/bounding capabilities, empty
inheritable/ambient sets, no new privileges, and the declared priority and limits. They
also observed the detached descendants adopted by init, in their original kernel groups
and separate sessions, with increasing progress counters. Init and LMKD logs matched the
native control identities and ordering.

Framework authority, CE availability generation, system server identity and boot identity
matched before and after. The VM stopped cleanly. Evidence was retained and sealed.

## Corrections and preserved failures

The first three attempts remain incomplete records, not passes of the current source.
They exposed init re-exec and readiness socket MAC boundaries, a Bionic signal default
configuration error, and missing task metadata/bootstrap library permissions. An earlier
policy check also confused any matching permission with complete permission coverage.

The implementation now uses a dedicated helper transition, explicit private socket
labels, actual task SID observation, bounded descriptor retirement across Epoll dispatch,
and ownership takeback only during verified empty directory retirement. Existing
neverallows were not bypassed. Init still lacks ptrace authority. Its nonfatal proc
attribute open-side ptrace diagnostic remained visible while the separately authorized
actual SID read succeeded. No denial was hidden to manufacture a pass.

## What this does not establish

The descendants were fixed trusted coordinator-role probe code, not arbitrary owner
programs crossing the ordinary owner MAC boundary. The new controls have compiled policy
negatives, but this trial did not exercise an ordinary application negative against each
new control. The LMKD operation was a controlled reaper invocation, not actual memory
pressure. SIGSTOP was a controlled delay, not uninterruptible kernel I/O.

There was no fresh CE withdrawal/regrant, forced numeric PID reuse, exhaustive transport
saturation, final independent zombie census or physical accounting release census. The
fixture limits and request counts are not product quotas. Existing Console/plain/Keep
behavior and defaults remain unchanged.

## Next gate

Connect the generic environment handoff to Andrix work admission and execution. Bind each
request to its original trusted platform/user/CE authority epoch before asynchronous
creation can outlive admission. Stop and revocation must permanently invalidate that
request, including an already queued release. Complete declared transitions retain all
privileged credential/resource changes internally. Ordinary owner execution continues
to accept an executable, arguments, environment and working directory.

Then qualify the ordinary owner credential boundary, independent work control and Unix
terminal lifetimes before moving presentation onto the new API. Pressure, suspend,
abnormal storage failure and physical phone qualification remain separate work.
