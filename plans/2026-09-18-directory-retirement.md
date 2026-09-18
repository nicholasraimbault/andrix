# Directory ownership during delegated retirement

Status: implementation candidate, not an accepted phone requirement or a qualified
Android cleanup result.

## Goal and ownership

Android must retire the exact delegated service tree even when its former owner left
nested directories without read or search access. No arbitrary filesystem path or
standalone credential, chown or chmod operation is exposed. The trusted supervisor owns
the complete Stop and retirement transition. Its private worker receives only captured
cgroup2 objects and authenticated instance metadata.

The first separate worker policy was rejected by two existing platform neverallows:
new domains cannot acquire general DAC override, and core domains cannot read unlabeled
`proc` files. Neither prohibition is changed. Own process metadata remains sufficient
for bootstrap inspection.

## Candidate mechanism

An explicit `ReclaimToWorker` retirement policy is part of the captured scope's limits
and private descriptor handoff. Only after Stop, initial process accounting, closed
mutation ownership and fresh kernel Empty may the cursor take back directory ownership.
Each object must be a verified cgroup2 directory inside the captured tree. Its owner and
group become the worker's actual effective credentials. Mode becomes 0755, permitting
observation but not management by other identities. Controls, regular files and unrelated
paths are not modified.

The Android helper retains CHOWN, not DAC override. SETGID and SETPCAP are temporary
bootstrap operations and are removed before accepting commands. The SELinux grant for
metadata changes is limited to cgroup2 directories. The helper has no owner work or CE
policy authority.

An `O_PATH` handle captures a directory even if its old mode is zero. `fchownat` and
`fchmodat2` with `AT_EMPTY_PATH` operate on that held object. There is no permission
fallback through a guessed pathname or `/proc` magic link. A harmless invalid descriptor
probe rejects unsupported `fchmodat2` behavior before this policy is accepted. The first
mechanism therefore needs that kernel ABI; it is not yet a minimum product kernel rule.

## Alternatives and costs

- General DAC override would ignore restrictive modes, but conflicts with the existing
  platform guard. Adding an exception merely to fit the helper is rejected.
- A supplemental group does not cover arbitrary nested modes or owner chmod changes.
- Changing filesystem UID between owners complicates the complete credential boundary
  and retains broader identity switching authority.
- Moving final filesystem operations back into init's critical loop defeats the chosen
  independently responsive cleanup lane.
- Ownership takeback follows the actual lifecycle transfer. It costs metadata syscalls,
  one temporary descriptor per visited directory, a capability limited by cgroup MAC,
  and a kernel ABI qualification requirement.

The unchanged credential policy remains the default for the native primitive. The new
policy adds no separately callable metadata API. Existing operation, depth, entry and
cumulative budgets remain in force. One quantum may include several bounded syscalls;
none of this establishes a wall time bound for kernel I/O.

## Failure and evidence

Errors keep the captured scope and cleanup obligation. Partial ownership or mode changes
are not rolled back into a fabricated active instance or reported as successful removal.
Exclusive namespace ownership remains essential; descriptors do not establish that
outside actors cannot mutate the tree.

Required gates include refusal while populated, unchanged credential EACCES behavior,
mode zero nested directories, interrupted cursor and worker recovery, captured identity
and bounds, actual Android cross UID takeback, and unrelated service progress. Host tests
under one UID cannot qualify CHOWN across Android identities or SELinux.

The first updated host gate passed optimized and sanitizer component units. Actual Linux
runs reclaimed mode zero nested directories only after Empty, retained ordinary EACCES
without the new policy, and resumed cleanup after worker death through the same descriptor
cohort. Independent responses continued during bounded steps. These are host process and
kernel results only. The selected Android and policy gate subsequently compiled, and
matching normal/test images were frozen at `c11e707`. A worker spawn failure prevented
actual directory retirement in the fresh Android run, so foreign UID takeback remains
unqualified.

Revisit if a supported phone kernel lacks the required ABI, a profile needs a different
retirement owner, a namespace cannot be made exclusive, or the extra operation/descriptor
cost exceeds the declared bounds. Do not weaken a guard or substitute a pathname
assumption to hide such a failure.
