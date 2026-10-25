<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native Accounts read view, candidate

This is a read only, current Android user metadata join. It is not normal login, CE
access, designation, a work submission, a recovery route or an account authority.
The accepted account authority and lifecycle decisions remain unchanged. Only user 0
has a supported backend. Another actual Android user receives unsupported and no
user 0 rows. A missing, conflicting, incomplete or newer cached store cannot become
an empty account list. Retirement does not delete data or release a UID.

The Package Manager already owns the store view and live pins. `inspectUser` rechecks
its caller supplied *internal* user and serial under the PMS lock, then projects only
the selected cached histories. The Settings wrapper supplies the same instance's
cached view, pins and cumulative holds. This service does not read a store or create a
handle. The Binder API has no target IDs. It derives the calling UID and Android user,
queries authoritative user information and rechecks the serial around the capture.
The typed response bounds attributable rows at 64, with package names at 255 chars.
Each row carries its stored lineage, so its principal ID is not mistaken for a
standalone global incarnation. An old pin's phase is reported only when the cached
history also matches the original issuance's lineage and signer set, or a restored
pin's first remembered original history. A later cached record that only reuses the
numeric ID, package, app ID, user and serial with another lineage or signer set is
unavailable, not ACTIVE. This check does not compare mutable lifecycle, suspension
or BODY/RESERVATION source. Unattributable holds remain unavailable evidence, not
account identities. Source, pin phase, lifecycle, stored suspension entries, store
status and completeness stay distinct. A complete creation binding in a selected
header with a genuinely missing body supplies attributable reservation identity,
lineage and pin metadata, but records no lifecycle or suspension. The store's
synthetic `ELIGIBLE` and empty suspensions make restoration possible, not an
observed body. The projection marks both fields NOT_OBSERVED for RESERVATION and
keeps the actual recorded lifecycle and suspension status for BODY, including
legacy bodies. The typed response and UI retain this distinction, and the UI
rejects contradictory combinations. No row reports current data availability,
an in-memory handle admission closure, execution eligibility, actors or notes.
Recorded RETIRED means retirement alone deleted nothing and released no UID, not
that data still exists.

The read Binder has its own service label and cannot be reached through the UID7500
lifecycle coordinator. The endpoint requires one exact installed Console package
without a shared UID, checks that UID's package record, and compares its current APK
signers *exactly* to the system image factory Console signers. The signer anchor comes
from the pinned framework `MATCH_FACTORY_ONLY` API, not a hard coded private key or
platform signing. It also checks the image copy's privileged system ext path. Updates
that rotate a signer, or an environment where the factory package cannot be resolved,
fail closed until their own continuity policy is qualified. The Console seapp rule
already names this package and its dedicated signer. SELinux find/call rules alone do
not authenticate Binder callers. This boundary does not resist a malicious platform
administrator replacing the factory image.

The UI makes no account query until explicit Refresh. One process scoped worker and
one replaceable pending request are independent of terminal control. A synchronous
Binder call may remain blocked despite Activity destruction, so no Activity creates
or shuts down its own worker. Pending work uses weak Activity references. Obsolete
pending requests are removed; a five second display timer changes the view to
unavailable but never claims to cancel a running Binder call. A dedicated Native
Accounts launcher alias starts in the read view without foregrounding the terminal
work controller; the existing terminal launcher keeps its behavior. A newer
refresh, navigation away, user change or Activity death discards a late result.
A service replacement between the worker's check after its RPC and its queued
Main callback also discards the old result, even if the previous Binder remains
alive. Acceptance checks the currently registered service's exact Binder identity
again at delivery. The pinned `ServiceManager.checkService` does not wait for a
service, and is not an account or PMS RPC. It can still incur kernel latency.
A match at delivery cannot promise future liveness or atomicity with later
registration changes.
Activity recreation saves only the view mode boolean, so a rotated Accounts view
does not foreground work or retain account results. Query failure does not display
an empty store. Opening Accounts detaches presentation
but does not stop work.

## Source and verification boundary

The selected `native-principal-pins.patch` now includes the exact tracked Settings
inspection fragment. Its selected profile pins the new Manager bytes, adapted
Settings candidate SHA and fragment. Its existing `native_principal_pins.py` guard
admits that candidate directly. The host Settings facade embeds the same fragment.
The committed 4cb Git object preserves the old Settings patch and profile. There
is no seventh patch family or second adaptation step in the selected directory;
the existing source-only candidate checker requires exactly six families. The old
B2 profile at its 4cb Git object, fixtures, output predictions and runtime
observations retain their historical scope; the selected current profile changes
for this genuine new API. Other source, license
and historical comparison pins that still name old bytes must be reconciled explicitly
before any Android build. Do not rewrite B2 observations to make this appear
previously qualified.

The pure Python source suite checks the selected recipe and fragment, immutable
projection, exact caller and signer predicates, typed response, UI staleness and
Soong/policy wiring. Separately, a bounded pure unified diff check applied both the
4cb and selected patches to pinned public Settings upstream SHA
`bff2de579d206a39be81ef0b798df8f6e845d2f28efbbcd63554ccffbddae5a1`, producing
Settings candidates `6c0e895d68c222436d1c34d123511875d8ede5f248c931ac843ff9ac2830c908`
and `eab4ec31c8bad9153065400db9935edb3de499f3ce4169bddd4e9a159625ffaa`. This is a
source consistency check, not an Android build. A Java host fixture is authored but
not executed here. Java compilation, AIDL generation, policy compile,
DEX examination and an Android guest proof require separately admitted work. The
current product already selects optimized system server compilation and its downstream
jar reference tracing. No broad keep rule for NativePrincipalManager is introduced.
Inspect the exact trace inputs and final DEX in the candidate: retain Inspection and
its read path, while dormant writers and release stay absent. Validate the factory
package query on the built Android image. None of these artifact or runtime checks
has been run for this patch.
