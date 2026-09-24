# Native principal location reference

Status: bounded experiment plan and host preparation. The first guest attempt stopped at
argument validation before location setup, so it supplies no location policy result. The
[notification reference](2026-09-24-native-principal-reference.md) qualified one capability
under a correct package/UID binding. This next case tests actual location permission, AppOps
foreground state and an existing request's revocation. It does not select a production launch
profile, foreground mechanism or stable native API.

## Questions

1. Can the same independently launched ordinary principal register and receive location data
   through the correct Android identity when its real grants allow it?
2. Does a grant limited to foreground use behave differently when Android classifies the UID
   as background or foreground?
3. When fine permission is withdrawn, does an existing fine request stop accepting newly
   injected data? Does the process remain alive, or does platform revocation terminate it?

Permission grant, UID importance, an active registration, a callback, provider health and
process retirement are separate observations. Silence alone answers none of these questions.

## Source basis

The inspected framework revision is `aab06a8bd44c4c2b58eeec780fde83baa9d43a40`.
`LocationManagerService.registerLocationListener` checks the real Binder package/UID and
permission level before registration. Request validation supplies the caller's WorkSource
when none is given and guards privileged request features separately.

`LocationPermissionsHelper` combines the runtime permission with AppOps. Its system adapters
watch permission and AppOps changes. `LocationProviderManager` reevaluates registration
permission, records foreground state, and refuses an active registration when it is not
permitted. It checks AppOps again at delivery. The foreground helper uses ActivityManager's
actual UID importance, not a terminal label or merely a running PID.

The provider manager also adjusts background request intervals. The normal minimum update
interval API permits delivery of data available more frequently than the requested provider
cadence. This fixture uses an explicit one second minimum interval and a controlled mock
provider. It does not request a throttle exemption or qualify real sensor cadence, background
power use or battery accounting.

## Vehicle and privacy

Use the same disposable principal and peer, distinct ordinary UIDs, the measured private
reference context factory and stock debug entry. Keep all known debug profile limitations.
The optional permission Activity still does not start, supervise or own a command process.

`LocationCommand` accepts only a fixed provider named `andrix_principal_test`. It never selects
GPS, network, passive or fused providers. It uses ordinary listener requests, no WorkSource
supplied by the caller, bypass flags, hidden AppOps flags, foreground service, wake lock,
background allowlist or policy override.

The controller creates that named mock provider through the platform's shell test API and
explicitly authorizes mock injection for the shell fixture if necessary. This is setup authority,
not a grant to the principal or peer. Enable location for the disposable Android user only
through its normal setting, and restore the original setting and mock operation mode on cleanup.
Do not alter the principals' AppOps modes to force a foreground result.

Inject only fixed synthetic coordinates, with a public timestamp marker for each injection.
The client reads no coordinates and never emits `Location.toString()`. It records only the
expected provider, mock status, marker time, elapsed time and callback count. An unexpected
provider or nonmock value fails the probe without exposing its contents. Inspect only the
named provider's service state, not a real device's location history. No physical phone or
personal profile is involved.

## Finite controls

### Binding and denied submission

Resolve installed package/UID identities and bytes, then require the process's kernel identity,
context and attribution to agree as in the notification reference. Require the fixed mock
provider to exist before requesting data; no fallback is allowed. With no location grants,
a request must refuse at the native permission layer. Keep an independently successful own
request as its positive counterpart.

### Background positive and live fine revocation

Grant ordinary coarse, fine and background permissions through explicitly labelled test setup.
Start bounded principal and peer commands without starting either fixture Activity. Observe
Android's UID state and the provider's registrations. Both must receive fresh marker callbacks;
the peer remains a health witness during the principal's negative controls.

Withdraw fine permission while the principal's fine registration exists. Observe the changed
permission state, actual service registration permission/activity and whether the original
command remains alive. Inject distinct markers only after the service's state has settled.
Require the peer to receive those markers and the principal not to receive them during the
bounded negative window. Before and after the window, require the same current registration,
its native permission/activity flags and a fresh principal heartbeat. Earlier queued callbacks
with earlier markers are not new data for that window.

Then grant fine again on the same registration and require a fresh marker positive. A
reactivated registration may legitimately receive a recent cached location. A separately
labelled transition marker replaces the final negative-window marker before reactivation;
its later delivery is neither a new positive nor a retrospective revocation failure.

If the platform kills the command, record that separately. Do not claim a surviving request
reacted to revocation when its process died. If the peer also stops receiving data, the negative
is inconclusive. Background throttling, provider failure, expiration or lost observation must
not masquerade as a permission result.

### Foreground policy on one live registration

Use a new bounded principal command with coarse/fine granted and background permission denied.
Keep a permitted peer command as the provider/delivery witness. Confirm the configured fine
and coarse AppOps modes, not just the grant command's return. Require the screen interactive,
keyguard unlocked, power saver off and location power policy unchanged for the scoped windows.
First observe the principal
UID as background and its existing registration as not permitted/inactive, with no new marker
callbacks despite witness delivery.

Start the optional principal Activity normally. Require its actual foreground UID state and
permitted/active registration before using new marker callbacks as a positive. Then return
Home, observe the real background state and AppOps settlement, and repeat the negative with
new markers. A foreground restoration on the same registration supplies another positive
against a dead listener. Do not use a fixed sleep as the oracle for foreground state. These
transitions deliberately reuse the one captured registration; they do not adopt a leftover
request from another command.

The visible Activity deliberately affects UID policy. This contrast does not qualify an
independent native foreground mechanism or justify a dummy resident Activity in the product.

### Retirement and cleanup

Each command has a finite client deadline, explicit callback/output bounds and a single
callback executor. The request uses zero displacement and a one second minimum update interval,
without a service duration or update count that could silently expire during a negative.
Synthetic markers are spaced at least two seconds apart. The client removes its listener and waits for that executor before reporting completion. The host
retains each command's transport identity, checks actual exit, and never stops work by a
reconstructed or recycled PID. A transport timeout remains unresolved until reconciled;
whole guest shutdown is containment, not retroactive proof of an individual Stop.

After requests retire, remove only the fixture provider, restore the changed settings and
uninstall the exact fixture packages. Verify acknowledgement and state separately. Preserve
partial/failing results. Use a fresh admitted guest and never reuse consumed queues or disks.

## Initial controller correction

The first fresh guest installed the exact fixtures, but the controller reused a readable
command label containing hyphens as the native command's nonce. The native argument guard
correctly refused it. No provider, location setting, permission grant or listener mutation
was issued. The packages were uninstalled and the guest, runner and capture closed.

The corrected controller derives the nonce from its run and command number, independently of
the display label, and validates all native argument vectors on the host before submission.
Host tests exercise the actual constructor path. Its early cleanup summary also distinguishes
an unchanged setting from a setting that required restoration. The original failure and summary
are retained; neither is a location capability result or reason to weaken the argument guard.

## Promotion limits

A pass would qualify only these finite location service behaviors on the reference identity.
It would not establish real GPS accuracy, user consent UI, production MAC/process/cgroup policy,
power/Doze/VPN behavior, CE withdrawal, another user's location policy or a native C ABI.
Production owner entry and foreground attribution remain coherent platform integration work,
not a reason to give ordinary native programs permanent root or relax service validation.
