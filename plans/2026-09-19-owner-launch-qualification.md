# First finite Android owner launch result

Status: passed listed controls at source `fbccb19`, assessed against native results,
independent process samples and stopped guest logs. This is a selected qualification
vehicle, not a new public work API or a replacement Console implementation.

## What was exercised

The generic Android supervisor supplied the enclosing captured environment. Andrix
bound requests to the original real platform instance, user and authority generation
before asynchronous creation. The fixed launcher verified its staging profile, installed
the owner filter and no new privileges state, claimed the atomic gate, and closed its
management handles before the fixed owner role transition. The final entry verified its
actual owner profile before using caller executable, arguments, environment and cwd.

The finite trial exercised:

- Compiling an ordinary program and shared library inside owner storage, then executing
  that owner program. The requested argv[0], cwd, environment and `LD_PRELOAD` worked.
  They were not supplied to the privileged bootstrap environment.
- Actual owner UID/SID, empty capability sets, inherited NNP/seccomp, resource membership
  and limits. The owner program reported only standard descriptors before opening its
  own files. Its cgroup write and Binder ioctl attempts were denied.
- A creator completion held after real fork and placement. Another owner workload made
  progress. Stop remained responsive, and the late completion added cleanup duties,
  not permission to execute owner code.
- A launcher actually stopped after preparation, with a published grant and a real wake
  already queued. Stop won before its entry claim. On resumption, the launcher refused
  the old gate without executing the owner program, then its exact scope was retired.
- Independent owner works. Stopping one did not stop the other or recreate it.
- Ordinary entry exit with a detached descendant still running. Explicit scope Stop,
  not entry exit or process session detachment, ended that descendant.
- An ordinary installed application denied access to the live control endpoint, both
  fixed entry executables and exact service start/stop controls. Kernel identity and
  matching positive controls were recorded. A helper refusing in main was not confused
  with the kernel refusing its exec.
- Actual manager exit with status 37 while owner work remained live. Android retired
  the old aggregate before creating an empty replacement. Old work was not replayed.
  A new explicit owner request then ran, followed by enclosing Android Stop.

The framework authority and platform process bookends matched. The owned instance
hierarchy was empty at the end. Independent samples corroborated live owner profiles,
resource membership and the stopped coordinator launcher. Init logs corroborated exact
retirement before replacement and the actual manager exit.

## Evidence chain and correction

The source passed 412 host tests. Focused immutable description and private descriptor
transport units passed optimized and sanitizer checks. Actual frozen Soong host tests
covered generic profile/event handling, LMKD transport, admission, description and launch
transport. Normal and selected native/policy checks passed. A fresh selected image and
matching tools were frozen and inspected. No fresh complete normal image is claimed.

The first Android attempt was incomplete. It reached the guarded owner shell, but the
ordinary build script supplied a temporary directory before it existed. Mksh validates
`TMPDIR` on assignment; it fell back to its Android default and correctly could not write
there. The failed attempt, normal cleanup and matching authority bookends were retained.
The corrected caller script created and reassigned its temporary directory and used a
literal source writer. No launcher permission or MAC exception was added. A fresh guest
and fixture were used for the successful attempt.

## Limits and next work

This was one finite controlled trial in one live platform authority epoch. It did not
exercise genuine CE withdrawal/regrant for these requests, suspend, real pressure,
uninterruptible I/O, forced PID reuse or exhaustive scheduling. A held creator completion
is not a blocked kernel syscall. Gate closure, process death, directory retirement and
physical resource accounting remain different facts.

Some Shell filesystem observations of private work directories were denied. They remain
unknown observations, not evidence of emptiness. The detached child's lifetime was
corroborated by the executed owner program's parent/child output, independent absence of
its initial entry, live scope accounting and subsequent captured cleanup. No separate
process sample of that detached child or final exhaustive zombie census is claimed.

The vehicle's two slots, fixed resource bounds, debug controls and thread arrangement
are not adopted product limits or interfaces. Work scopes are not mutual isolation of
programs belonging to the same owner. Existing Console/plain/Keep behavior remains.

Next qualify original epoch invalidation across genuine CE withdrawal and normal
credential recovery. Preserve the already approved fault facility's caller and consent
guards rather than treating a debug build as authority. Then complete the ordinary work
registry/API and terminal presentation integration under the accepted Unix lifetimes.
