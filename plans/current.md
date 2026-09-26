# Current work

## Governing direction

Build the [owner composable Android OS](../docs/vision.md) accepted in the
[vision revision](2026-09-21-owner-composable-android.md). Andrix owns its platform design,
policies, packages, signing, updates and recovery. GrapheneOS is the initial engineering
foundation, not a permanent policy ceiling. Native Unix programs and APKs are equally
important parts of one Android/Bionic system.

Daily programs use ordinary authority. General administration, including arbitrary root
commands and shells, requires deliberate authorization. Source availability alone is not
practical ownership: changing a component needs an understandable build, authorization,
installation, activation and recovery path.

Follow the [design method](../docs/architecture.md#design-method). Proofs inform the design;
they do not require retaining prototype code or turning test limits into product restrictions.
Correctness, coherence and owner control guide reuse, refactoring and replacement.

## Prototype and design tracking

The [design evidence register](../docs/design-evidence.md) connects observed results,
accepted contracts, proposed mechanisms and remaining gates. Dated plans describe reusable
methods and scoped outcomes. Neither a successful fixture nor acceptance of a requirement
qualifies a production implementation automatically.

Detailed operating records, local configuration, credentials and raw captures remain private.

## Current implementation

The owner endorsed the consolidated direction and resumed bounded implementation. The
[deliberate decision audit](2026-09-25-deliberate-decision-audit.md) covers the accepted architecture
and all 18 evidence areas through 58 grouped decisions, with selected source checks and one bounded
host reproduction. It is not whole platform or phone clearance.

The resulting [integrated platform model](2026-09-25-integrated-platform-model.md) now joins native
identity, work, UID policy, API effects, managed environment leases, signing, deployment and recovery
in one proposed ownership and lifecycle model. It contains recommended implementation hypotheses,
credible alternatives, event/disruption matrices and complete journeys that should falsify or
support the design. It is not a new accepted architecture or a claim that the joins work yet.
Accepted policy remains unchanged. The [terminal parser logging correction](2026-09-25-terminal-diagnostics-privacy.md)
now has a matching failing control, 156 passing host parser/adapter checks and a successful
`AndrixTerminal` Android module build with artifact verification. Device logging and broader
runtime privacy remain separately unqualified. The [native identity record and slot storage component](2026-09-25-native-identity-store.md)
now has actual Java codec/filesystem checks and a successful Android `services.core` module
build. The [PMS consumer integration](2026-09-26-native-store-pms-consumer.md) now has 24 focused
host checks, including actual slot transactions beneath the manager, negative recovery state and
code/data cleanup fences. Its actual Android `services.core` build passed at `e8dc35c`. Boot
recovery, owned restoration and lifecycle integration remain separate gates. No new factory or account path was activated.

## Current milestone

The current work is implementing the native entry and Android integration for a sustainable
owner controlled Android lineage, while qualifying its authority contracts before activation.
Android is the settled platform.
The proposed [native principal contract](2026-09-24-native-principal-contract.md) covers ordinary
owner programs as subjects of Android policy. The proposed
[owner trust, selection and deployment contract](2026-09-24-owner-composition-contract.md)
covers installation authority, native state, durable effects and recovery. These are drafts
for review, not newly accepted architecture or runtime qualification.

They refine the [composition assessment](2026-09-23-composition-architecture-assessment.md),
which separates owner intent, resolved inputs, exact artifacts, compatibility, authorization
and observed deployment. The [source mechanism comparison](2026-09-24-integration-mechanism-assessment.md)
now distinguishes principal representation, API binding and execution lifetime, and maps
separate package, privilege, image and APEX trust checks. It proposes a recognized ordinary
principal reference case, followed by location and mobile policy tests. These are source
findings and proposed experiments, not runtime results or a selected production mechanism.
No principal representation, key topology, package language, store, version encoding or
universal update mechanism is selected.

The [ordinary principal reference plan](2026-09-24-native-principal-reference.md) now has a
bounded source vehicle: optional permission UI and a separately invoked ART command, using
stock `run-as` only as a diagnostic entry. Fifty host parser/guard checks and public SDK
compilation passed. Three ordinary APK artifacts were built and verified, including their
package, permission, signer and debug flag distinctions. The standalone build used API 36
compile/code generation inputs with API 37 minimum and target declarations unchanged.
Two initial runs established entry controls and then localized an incorrect inherited
operation package. The corrected reference at `c1a51ff` now passed the finite notification
service matrix: own granted positives, foreign package refusal, cancellation, denial of new
posts after revocation, and separate grant behavior in a fresh secondary Android user. Exact active
service records were independently decoded. No fixture Activity or foreground service was used.
Privileged fixture grants are not user consent UI proof, and service retention is not visible
notification delivery. Shell groups/cgroup inheritance and the private factory remain diagnostic
limits, not a production launch profile. The
[location reference](2026-09-24-native-principal-location.md) has now passed its finite mock
provider matrix: background delivery under an explicit grant, live fine revocation and regrant
on the same listener, foreground grant behavior across observed UID transitions, denied new
requests and retirement. A permitted peer, native registration state and fresh markers guarded
against false conclusions from silence. Earlier failures remain separate. The debug launch
profile and incomplete private bootstrap are still not a production native environment.

The [native runtime integration proposal](2026-09-24-native-runtime-integration.md) now sets out
that entry, binding and foreground contract for review. It recommends starting with a Package
Manager backed native principal role, compares direct native integration and managed/native
runtime representatives, and preserves work/CE/Stop ownership. The pinned platform already has
a guarded native application attachment and native zygote route for isolated APK services;
that source is a reuse candidate, not a qualified ordinary owner launch. Actual process/UID
policy, one coherent cgroup hierarchy, authentic runtime state and presentation delegation must
fit together. The owner has approved bounded disposable experiments, not a production
representation or authority profile. The [runtime route fixture](../tests/native-runtime/README.md)
starts by comparing an ordinary managed service with the existing isolated native service route
on an unchanged image. Its instrumentation and lifecycle controls are not an ordinary Unix entry
or foreground policy pass. Its first runtime comparison now observed both routes starting and
answering Binder calls. The managed service received a complete SDK bootstrap. The native
isolated process was killed as `ISOLATED NOT NEEDED` after unbind, with no observed destroy
callback, so the complete lifecycle matrix remains false. This narrows reuse: native attachment
is real, but isolated component lifetime is not the Unix work contract. Real sensors, VPN,
power/accounting and further user/lifecycle cases remain independent gates.

The [first principal launch implementation](../owner/principal-entry.md) is now connected to the
work runtime as a separate inactive path. It carries an immutable principal binding and captured
home through the private handoff, verifies actual credentials, preserves independent Stop and
closes control descriptors before ordinary execution. The manager remains at the principal UID;
individual work does not select or switch privileged credentials. The legacy reserved UID path
retains its Binder denial. Host and Linux supervision regressions do not qualify this new path
on Android. The authoritative account designation/UID lifetime, trusted manager specialization,
principal aware lifecycle binding, native API adapters and policy/resource integration remain
required before activation. No product selects the new entry yet.

The [Package Manager native reservation component](../owner/platform/principal-pins.md) now
adds persistent identity pins, allocator fencing, exact handles and durable retirement markers
initially inside Android's own settings. Normal uninstall, replacement and clear data paths are fenced
against live reservations. JVM/component checks passed and the actual Android `services.core`
module compiled. This is not a device runtime pass, an owner designation interface or a manager
factory. Complete settings loss/corruption, older readers and the native boot/recovery barrier
remain activation gates; the initial adapter supports only user 0. Existing CE and Package
Installer adaptations were preserved. Exact installed subject selection now binds designation
to the installed object, signer set, version, UID and user serial, without making selection a
grant. The [recovery redesign](2026-09-25-native-recovery-boundary.md) now proposes a small native
reservation store owned by Package Manager, separate from ordinary package settings. Stable UID
slots and recovery copies would preserve allocation holds even when account details are damaged,
so the affected native account can stay unavailable without stopping the phone. The separate
[storage component](2026-09-25-native-identity-store.md) is now module compiled. Its
[PMS consumer](2026-09-26-native-store-pms-consumer.md) is implemented with host checks, but the
recovery behavior is not yet Android runtime qualified. Unsupported OS data reuse is outside the supported migration path;
total destruction of every authority copy is a disaster case, not a reason to block ordinary
integration. No fixed UID range, permanent nonreuse policy or catastrophic recovery default was
silently selected.

The deciding gates are:

1. Establish useful ordinary native Android capability access with coherent identity,
   permission, attribution, revocation, user, network and lifecycle policy. Direct native
   execution remains independent of separate APK registration for every program.
2. Carry an owner platform variant and upstream fixes across real upstream changes, making
   conflicts and missing fixes visible. Compare explicit trust and selection alternatives
   rather than beginning with version code manipulation.
3. Complete a durable component transaction with exact artifacts, all required signatures,
   publication, native installation and recovery from interrupted or uncertain outcomes.
4. Establish real APK, APEX and image activation boundaries, including shared package code
   versus per user data and the limits of restoring an earlier software composition. State
   the signing threat boundary for later locked operation separately from workshop signing.

An APK versionCode is an installation ordering input, not a complete source or owner
selection model. Image assembly from cached components need not recompile the whole OS.
Framework integration is legitimate where it produces the cleaner complete contract.
The exact mechanisms remain under investigation.

## Product checkpoint

There is no supported Andrix release or buildable Pixel deployment product. Current results
are bounded emulator, host and artifact qualifications, not general hardware or phone claims.

### Native development and work

The ARM64/Bionic prototype supplies a terminal/editor, C/C++ compilation, Make, LLDB and
tmux under an ordinary owner identity. Android application boundaries and authenticated
read only `/usr` remain intact. The original Keep path remains off by default while the
separate work and terminal model is developed.

Selected service controls have exercised ordinary owner execution, detached descendants,
independent Stop, genuine CE withdrawal and recovery, stale identities and cleanup. Their
qualification and remaining limits are summarized below and in the design evidence register.

### System component modification

The [SystemUI component loop](2026-09-22-systemui-component-runtime.md) passed focused builds,
staged APK activation, visible changes and forward source restoration on one compatible
platform cohort. Native execution and saved data were checked afterward. Higher version
restorations were new artifacts containing good source, not arbitrary APK or data rollback.

Wrong signer, absent sidecar and mismatched sidecar controls were refused in their recorded
scopes. The [file verification restoration correction](2026-09-22-package-verity-restoration.md)
removed redundant setup without changing subsequent signature or digest verification.
Ready remains distinct from applied, compatible or healthy.

### Signing identity and artifact flow

The [portable recovery default](2026-09-22-installation-key-recovery.md) is accepted: an owner
held encrypted recovery bundle and a protected device signing copy. Recovery must not depend
on the original hardware or vendor approval. Signing identity recovery is not CE data backup,
hardware bound app secret recovery or live rekeying.

The [recovery vehicle](2026-09-22-signing-identity-recovery-proof.md) exercised independent
recovery of disposable identities and ordinary Android crypto interoperability. The
[protected request vehicle](2026-09-22-protected-signing-request.md) then qualified finite
AndroidKeyStore import, exact approval, credential authentication, signing and refusal controls.

The [APK artifact flow](2026-09-23-protected-apk-artifact.md) qualified capture of an immutable
project APK, protected signing, verification, export, ordinary installation and execution with
the expected identity. Decline, authentication cancellation, retained request retry, changed
context refusal, completed view replay, broker replacement and cleanup were tested in their
stated scopes. This does not qualify a general platform signer or owner enrollment service.

The [expanded public trust inventory](2026-09-23-apex-trust-inventory.md) covers 180 APK files
and 94 APEX containers with 72 certificate identities, including 33 APKs inside APEX payloads.
Payload signatures, hash trees and declared key bindings were verified. These are public
artifact relationships, not proof that the owner possesses every observed key or that every
artifact is active. Available SDK 37 lineages are not historical installed state.

The latest recorded full host suite has 520 checks. Host tests, artifact inspection and actual
Android controls remain separate evidence layers.

## Authority and privacy boundaries

The [accepted signing default](2026-09-23-signing-authorization-scope.md) is one explicit
approval and fresh credential authentication for a complete protected signing transaction.
It does not select a timed key policy, grant authority to later requests or make ordinary
application builds privileged. Platform transaction token issuance and timed key use remain
unqualified alternatives; the current prototype's key policy is unchanged.

No personal installation identity has been provisioned. Complete component signing formats,
installation trust roles, durable publication, accepted operation loss and hardware custody
remain separate work. The lab shell interface is not a product owner interface.

Earlier credential recording checks overstated their scope: adbd could record credential
dependent command arguments despite exclusion from a wrapper's own log. Those claims were
corrected, and sensitive captures remain private. The reusable
[recording method](../docs/development-artifacts.md#keep-credentials-out-of-command-records)
uses constant service arguments and private stdin, with guarded input and inspection of actual
captures. It does not promise universal absence of logging, memory disclosure or physical copies.

## Retained Unix milestone

The accepted model is that Android supervises environments, Andrix manages work, the kernel
enforces containment and Console is a client. Terminal detach, terminal hangup, initial process
exit and complete work Stop remain distinct. Continuation, restart, wake, network exposure and
locked input are separate permissions.

The selected work service is not yet the replacement Console path. Existing plain and Keep
behavior remains until its successor is qualified. Fixed slots, property transport, lab
request counts and proof resource limits are not permanent product policy.

## Unix qualification history and remaining gates

The detailed mechanism results remain in their respective plans:

- [Work and terminal separation](2026-09-16-work-terminal-separation.md) and
  [supervision design](2026-09-16-unix-work-supervision.md).
- [Factory comparison](2026-09-17-work-factory-comparison.md),
  [delegated contract](2026-09-17-delegated-supervision-contract.md) and
  [finite Android service qualification](2026-09-18-delegated-service-qualification.md).
- [Admission gate](2026-09-18-work-admission-gate.md),
  [ordinary owner launch](2026-09-19-owner-launch-qualification.md) and
  [original admission across CE withdrawal](2026-09-19-owner-admission-ce-trial.md).
- [Registry](2026-09-19-work-registry-core.md),
  [gateway and descriptor ownership](2026-09-19-work-gateway-boundary.md),
  [service integration](2026-09-20-work-service-integration.md) and
  [runtime controls](2026-09-20-work-service-runtime.md).
- [Service CE behavior](2026-09-20-work-service-ce.md),
  [uncertain replies](2026-09-20-work-service-uncertain-replies.md),
  [catalog capture](2026-09-20-work-catalog-capture.md) and
  [initial request identity recovery](2026-09-20-work-request-recovery.md).

Remaining gates include complete stream/reservation recovery with the actual CLI, further
pending creation and entry races across CE changes, terminal integration, resource pressure,
suspend, storage failure and forced identity reuse. Request lookup does not authorize a new
submission. Stop acceptance does not establish process exit, an empty group or cleanup retirement.

The [record retention contract](2026-09-19-work-result-retention.md) keeps minimal security
records separate from optional persistent activity history and output capture. Storage and
recording must not block control operations or become ambient authority.

## Supporting workstreams

- [Owner authority and signing](2026-09-21-owner-authority.md): general elevation, individual
  installation authority, protected signing and independent recovery.
- [Android accounts with Unix](2026-09-21-android-unix-accounts.md): actual per user credentials,
  MAC, homes, work and CE lifecycle, not multiple pathnames under one principal.
- [Rolling composition and installation](2026-09-21-rolling-composition.md): retained owner
  choices, compatible sets and controlled activation under one recommended/custom model.
- [Pixel integration](2026-09-21-pixel-integration.md): physical phone qualification and later
  owner keyed locked operation, distinct from the current workshop proofs.

On-device ordinary component development remains an end goal. Host assistance does not become
a permanent requirement because the current proofs use it. Unsigned native programs and general
administration remain owner capabilities; ordinary software does not automatically become a
platform package. A parallel glibc distribution and alternative desktop compositor are not
product tracks. Dedicated agent architecture remains outside the current product work.

## Foundations and references

- [Product vision](../docs/vision.md), [accepted architecture](../docs/architecture.md) and
  [design evidence register](../docs/design-evidence.md).
- [Workshop component workflow](2026-09-21-workshop-components.md).
- [GrapheneOS migration](2026-09-08-grapheneos-migration.md) and
  [Android lifecycle integration](2026-09-13-android-lifecycle.md).
- [Native compiler](2026-09-11-native-compiler.md), [C++ defaults](2026-09-11-cxx-defaults.md),
  [Make](2026-09-11-native-build-tools.md) and [debugger](2026-09-12-native-debugger.md).
- [Terminal and input](2026-09-10-owner-tools.md), [cold attachment](2026-09-11-cold-attachment.md)
  and [native tmux](2026-09-13-retained-terminal.md).
- [Reusable development artifact handling](../docs/development-artifacts.md).
