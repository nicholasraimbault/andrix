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
signers *exactly* to the system image factory Console signers. The factory record is requested through the pinned framework `MATCH_FACTORY_ONLY`
API, not a hard coded private key or platform signing. That API can fall back to the
current system package when no disabled factory record exists. Equality with that
same record is not independent proof of factory provenance. The endpoint also
checks the returned record's privileged system ext path and metadata. A data update
needs a separate factory image record or refusal; an unupdated image copy still
needs independently verified image origin. These artifact and runtime provenance
gates remain open. Updates that rotate a signer fail closed until their own
continuity policy is qualified. The Console seapp rule
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
for this genuine new API. Pin reconciliation must distinguish those source epochs.
The isolated builds described below checked their current staged source and selected
patch and profile commitments. They did not complete a global reconciliation of
historical license only pairs, carry results or B2 comparison pins. Those old
mappings remain tied to their verified old source context, not an assertion that
the new API is only a license header change. Successful compilation does not
satisfy that outstanding historical qualification. Do not rewrite B2 observations
to make this appear previously qualified.

An actual policy build after the Java and DEX gates exposed a lookup conflict.
The platform's broad `service_manager_type` find grants for `shell`, `system_app`
and `traceur_app` included the new service, contrary to its foreign app
neverallow. Removing `system_server_service` would not resolve that conflict.
The candidate fix extends the existing private `owner-session-policy` bridge to
four pinned files. It declares this exact new service type under the existing
owner session flag and excludes only that type from the three broad lookup sets.
The extension retains its service registration and both neverallows, and the
Console's explicit lookup and Binder call remain unchanged. No public policy API
or permission for another service type is added. Unflagged source expansion
retains the existing rules. The four file source guard and focused fixtures do
not by themselves establish a successful policy build. A later normal compiler
run against a fresh committed source snapshot supplies the separate artifact
result described below.

The pure Python source suite checks the selected recipe and fragment, immutable
projection, exact caller and signer predicates, typed response, UI staleness and
Soong/policy wiring. Separately, a bounded pure unified diff check applied both the
4cb and selected patches to pinned public Settings upstream SHA
`bff2de579d206a39be81ef0b798df8f6e845d2f28efbbcd63554ccffbddae5a1`, producing
Settings candidates `6c0e895d68c222436d1c34d123511875d8ede5f248c931ac843ff9ac2830c908`
and `eab4ec31c8bad9153065400db9935edb3de499f3ce4169bddd4e9a159625ffaa`. This is a
source consistency check, not an Android build.

The Java projection fixture has now compiled with 47 source files under the pinned
host JDK, `--release 17`, `-Xlint:all` and `-Werror`, and passed with assertions enabled.
It exercises actual record/store and manager code through declared host Android
facades. The cases cover immutable empty and BODY views, header reservations with
unobserved lifecycle and suspension, original lineage and signer mismatch, missing
and incomplete state, conflict, newer format and changed user serial. The query
leaves the fixture's stored bytes unchanged. This is host component evidence, not
Android Package Manager, Binder caller authentication, service replacement or
SELinux execution.

A second host gate compiled the actual query endpoint and controller with 20
controlled Android and AIDL shaped facades. Its 46 endpoint cases and 21 controller
cases passed, then an independent compile reproduced all 37 class digests and the
same case results. The controller cases cover a queued reply followed by service
replacement while the old Binder remains alive, stale responses, observation state
rendering, and one blocked worker across eight controller recreations. The tests
release their owned blocked call and retire the executor before exit. The manager
in this gate is a capture facade, not the production projection. Caller IDs, package
and factory metadata, signer sets, scheduling and service registration are supplied
host facts. These results exercise real Java branch and queue logic, not kernel
Binder identity, cryptographic signatures, actual factory provenance or Android UI.

A separate bounded host gate has now generated the three committed AIDL files
with the actual AIDL compiler, in both Java and NDK modes. It produced three Java
files and twelve NDK source and header files. Both compiler invocations returned
zero; the inputs and pinned compiler and library bytes stayed unchanged. The
compiler SHA256 was
`5698d499ed01db6db5d74282a56d83b5325d657659eea21249adbf7a0eb3a3fe`.
This binds the observed tool, not a reproduced compiler build. It is a code
generation observation, not qualification of the execution supervisor or Android.

The generated interface has the argumentless `inspectCurrentUser` transaction,
typed snapshot return and declared row and snapshot parcel order. Generation does
not itself enforce the endpoint's 64 row limit. No generated Java or C++ code was
compiled or linked in that generation gate.

A later bounded host gate compiled those same three generated Java files against
the actual Android API 37 public SDK stubs, not hand translated Android facades.
The SDK jar SHA256 was
`90bf8b80697f086b6fd7cc3956b436a34e2a6cf7193f7fed1343b63625c97ef2`.
The pinned JDK 25 compiler targeted Java 17 with `--release 17`, `-Xlint:all`,
`-Werror` and `-proc:none`. It returned zero with empty stdout and stderr and
produced nine class files, all class version 61. The compiler SHA256 was
`a5f3fb28e08804fb3bc55522625e7dff9c686172aac7f7067b1d839297c73001`.
The owned process was directly waited and its group retired. The original Java
source bodies remained unchanged; no generated sources or class files were
committed.

This qualifies the observed compilation of the generated Java transport types
against that SDK surface. It does not compile the production endpoint or Console,
qualify Android module compilation, compile or link the NDK output, execute Binder
parceling, or establish final DEX, policy, image correspondence or Android runtime.
Those gates remain separate.

A subsequent bounded gate compiled the three existing generated NDK C++ files
with the official NDK r30 package, revision `30.0.16248370`, and the selected
Android source tree's real NDK Binder headers. The compiler SHA256 was
`ad535f0b6fc303edba958b51636169ff0291c6e36463236c99ff8abcaa34247c`.
It targeted `aarch64-linux-android37`, used C++17 with `-Wall`, `-Wextra` and
`-Werror`, and explicitly selected the NDK's Bionic and Android libc++ headers.
A forced include asserted Android, Bionic, ARM64 and API 37 during all three
compilations. This was a target assertion, not an Android runtime observation.

One compiler driver invocation with integrated frontends returned zero, with
empty stdout and stderr, and produced three ELF64 relocatable ARM64 objects.
The owned process was directly waited and its group retired. The compiler's
recorded dependency files named 727 source and header inputs; their actual bytes
matched the pinned input map, with no host system headers used as Android
inputs. The original generated source and header bodies remained unchanged.
The four parcelable Bn and Bp placeholder headers were not compilation inputs.
No generated source, object or downloaded toolchain is committed.

This qualifies only the observed compilation of those generated C++ transport
bindings against that target header surface. It does not link a native library,
compile the production endpoint or Console as Android modules, execute Binder
parceling, or qualify DEX, APK, policy, image correspondence or Android runtime.
The NDK uses its Android libc++ ABI; these objects do not establish compatibility
with a different platform libc++ configuration or replace a Soong module build.
The prior AIDL compiler's source and build provenance remain unconfirmed.

A further bounded Java gate compiled the actual production Console Activity,
terminal and Native Accounts controllers, protocol sources, default feature
selection and the three generated Native Accounts Java bindings. It used the real
Android framework, Termux and session interface header jars from an existing
Android build, the API 37 public SDK jar and the declared AndroidX annotation
provider, not hand written Android or AIDL facades. The framework header jar
SHA256 was
`490961f955830ac0f43bc8a880b511eccc93568294e796e728376feb5a3b3d17`.
These pinned jars establish a compile API surface, not correspondence to a new
feature image or a newly generated Soong graph.

The first compile succeeded with eight warnings. Six identified the missing
annotation provider in that invocation, and two identified deprecated Console API
uses. A separate strict compile added the actual provider and used the reviewed
Console API changes: `TypedValue.applyDimension` preserves the 14 SP terminal
size with nonlinear font scaling, and the owner requested keyboard call no longer
uses the deprecated `SHOW_IMPLICIT` flag. The strict JDK 25 invocation targeted
Java 17 with `-Xlint:all`, `-Werror` and `-proc:none`. It compiled thirteen source
files into 32 class files, all version 61, with zero exit and empty diagnostics.
Its owned process was directly waited and its group retired. The first compile
and warnings remain separate evidence.

This qualifies observed Java compilation of those client sources against the
specified real headers. It does not compile the production server endpoint,
qualify a Soong module build or optimized final DEX, create or sign an APK, execute
Binder calls or the Console UI, or establish policy and image correspondence.
Font scaling, keyboard behavior, accessibility and the UI lifecycle still need
Android runtime observations.

A later standalone API gate compiled the actual query endpoint, the full adapted
Android Settings source, all six native identity helper sources and the three
generated Java bindings. It used real services, framework, libcore and Permission
API artifacts from an existing Android build, plus the API 37 SDK, not a mock
Settings class or Android facades. The complete Settings source supplied the
cached inspection method. An earlier actual compiler invocation exposed a missing
Permission API dependency; the later invocation supplied the actual declared
`service-permission.stubs.system_server` provider. No source check or type was
replaced to bypass that diagnostic.

The pinned JDK 25 compiler targeted Java 21 with `--release 21` and `-proc:none`.
It returned zero and produced 80 class files at version 65 from eleven sources.
It retained thirty unchecked warnings and a deprecation note from the Android
Settings source; this was not a warning free gate. The owned process was directly
waited and its group retired. A subsequent gate compiled all nine Java sources
selected by `andrix-owner-lifecycle` with Keep and fault controls disabled. It used
those newly compiled PMS and transport classes, the real Android API artifacts
and the existing lifecycle interface header. That invocation returned zero with
empty diagnostics and produced 23 class files at version 65. Its process was also
directly waited and retired.

These are observed source API compilations, including the production endpoint,
its cached PMS implementation and the selected lifecycle Java source set. They do
not establish a completed current Soong dependency graph, optimized server jar,
final DEX, APK, policy or image. The existing API artifacts do not establish
correspondence to a new candidate image. No server, Binder, store, signer or
lifecycle operation was executed by these compile gates.

A subsequent candidate gate completed the current Soong main graph for the
selected services, owner lifecycle and Console roots. The normal generated
combined Ninja entry parsed successfully. Its actual upstream command closures
and dry runs were checked before requesting unsigned Java outputs. No generated
Ninja file was repaired, missing dependency waived, optimization disabled or
signer consuming APK, APEX, image or install goal requested.

The normal Soong UI product configuration and Ninja stages then built the three
combined Java implementation jars and their actual dependencies. The completed
current graph was reused explicitly, not presented as a clean build. The invocation
returned zero, its owned group retired, and the critical product and source input
hashes remained unchanged. Inspection found these outputs:

| Combined implementation | Bytes | Class files |
| --- | ---: | ---: |
| `services.impl.jar` | 34,480,394 | 13,993 |
| `andrix-owner-lifecycle.jar` | 53,131 | 41 |
| `AndrixTerminal.jar` | 2,000,722 | 1,138 |

The services jar contains the full adapted Settings class and all six native
identity helpers. The owner and Console jars contain the actual endpoint,
controller and generated Binder types, not host facades. Selected feature classes
have class version 65. The build retained 1,574 warning lines from its full
closure. This is not a warning free result or a claim that every warning was
attributed to a particular module.

A separate bounded invocation built the actual unsigned R8 DEX jar targets for
`services`, `andrix-owner-lifecycle` and `AndrixTerminal`. It also returned zero
and retired its owned group, with shrinking and the selected optimization settings
unchanged. Each of the three R8 invocations warned that API level 37 was not
supported by that compiler and that API level 36 or earlier should be used. These
warnings were retained, not suppressed. Completion does not establish API 37
runtime or release toolchain qualification.

The resulting `services.jar` contains three DEX files. The owner and Console jars
each contain one. Their DEX 039 headers, checksums and encoded class and member
definitions were inspected. The actual owner DEX's native PMS references matched
public classes and members in the optimized services DEX, including `inspectUser`,
its immutable inspection and row fields, enum values and unavailable or unsupported
factories. Two enum `ordinal()` references are inherited Java API calls, not
missing declarations on the enum itself. The kept owner service class, public
Context constructor and `onStart` entry point were also present. This is a
selected structural linkage check, not full ART verification or a complete runtime
classpath check.

The current product's downstream reference tracing generated keep rules from the
actual owner combined jar against the actual services combined jar. Those rules
cover the observed inspection boundary. No broad hand written Manager keep rule
was added. The optimized Manager declares only its constructor,
`authoritativeSerial`, `project`, `signerDigests` and `inspectUser`; dormant writer
and release entry points were not newly retained to force the check to pass.
Source review alone had not established this generated trace coverage. The actual
trace input and optimized definitions supplied the later artifact evidence.

These gates qualify observed current Java module compilation, unsigned R8 output
and that selected retained interface. They do not establish a signed APK, final
policy or image correspondence, factory signer origin, service startup, Binder
execution, store behavior or lifecycle operation on Android. Validate the factory
package query and the remaining runtime cases on a separately admitted image.

A fresh candidate at the four file bridge source commit then built the selected
system extension CIL, service contexts, seapp contexts and MAC permissions, along
with `sepolicy_neverallows`, `sepolicy_test` and the platform shared variant of
`andrix_platform_lifecycle-ndk`. The normal product configuration and Ninja
invocation returned zero and its owned process group retired. The earlier failed
policy result was preserved, not turned into a pass or bypassed. Unchanged build
recipes and interface sources allowed explicit reuse of the completed graph and
ordinary build cache; the changed policy sources were compiled normally.

The emitted CIL contains the Console's exact service lookup allow and the system
server's add and find allow. Its foreign app and native owner neverallows remain.
In a separate copied configuration control, adding lookup allows for `shell`,
`system_app`, `traceur_app`, `andrixd` and `andrix_owner` produced the expected
neverallow compiler refusal for all five. This is compiler evidence, not a
measurement of Binder or SELinux behavior on a running phone.

The emitted service context names `andrix.owner.accounts`. The seapp result maps
the privileged `dev.andrix.terminal` package and its selected seinfo to the
`andrix_terminal` domain and data type. MAC permissions encode the newly generated
public compile certificate selected for that candidate. That public certificate
was the only key related policy input admitted; no signing goal was requested
and no APK was signed. This lab certificate mapping does not establish an
immutable factory signer or image origin.

Policy diagnostics were retained. The stock policy test returned zero while
emitting 128 messages about an absent
`isolated_compute_allowed_property_type` attribute. Its source permits an empty
or unused attribute and skips the corresponding property check when absent.
The zero exit is not a claim that this optional branch or all policy behavior was
exercised.

The generated NDK transport compiled and linked as an ARM64 ELF64 shared library,
with `libbinder_ndk.so`, platform `libc++.so`, `libc.so`, `libm.so` and `libdl.so`
as its recorded dependencies. This qualifies the observed platform shared
variant, not the distinct SDK variant or compatibility of the earlier standalone
NDK objects with platform libc++. No target library was loaded or executed.

## Remaining Android artifact and runtime gates

Use an isolated candidate at the selected upstream revision and the exact feature
source, without adopting it into the B2 source epoch. Bind the complete selected
six family patch and profile inventory. The current Settings inspection fragment,
Manager helper and adapted Settings postimage are one coherent source change, not
a seventh family or a hash only repair of historical licensing predecessors.

The concrete source module roots are:

- `services`, through `services.impl` and `services.core`, for the adapted PMS and
  cached inspection API. The core recipe collects its Java sources into
  `services.core.unboosted`, then the priority boosted and combined outputs.
- `andrix-owner-lifecycle`, which compiles against `services.impl` and statically
  links `andrix_platform_lifecycle-java`.
- `AndrixTerminal`, which compiles the actual Console and controller against the
  generated Java interface. Its module references the dedicated certificate;
  naming this target is not permission to use signing material. Compile only or
  unsigned evidence and any signer consuming step must be scoped separately.
- `andrix_platform_lifecycle-ndk`, as well as Java AIDL generation. The unstable
  interface enables Java and NDK. Lifecycle enabled native consumers select the
  NDK dependency even though this read endpoint uses Java.
- `AndrixOwnerLifecycleOverlay`, which selects the system server service.

These are module roots, not a claim that their total dependency graph or build
allocation is small. Establish the actual staged source, generated target graph,
toolchain identity, output capacity and inode forecast before compiling anything.
A successful host facade compile does not supply those inputs.

The product selects `PRODUCT_DEVICE := andrix_cf_arm64_only`. Its tracked board
recipe includes `owner/sepolicy` with `ANDRIX_OWNER_SESSION=true` and also
`owner/platform/sepolicy` with `ANDRIX_OWNER_LIFECYCLE=true`. Verify those directories
in the actual staged vendor tree, rather than infer final inclusion from source
paths. Relevant policy roots include `selinux_policy_system_ext` and its
`system_ext_sepolicy.cil`, service contexts, seapp contexts and MAC permissions.
Check the selected product's combined policy and neverallow tests as well. The
source defines `selinux_policy`, `sepolicy_neverallows` and `sepolicy_test`; actual
outputs and their transitive scope must be bound to the candidate.

Retain source and output commitments for these artifact checks:

1. Retain the actual Java and NDK AIDL generation commitments. When those inputs
   change, recheck the zero target argument query, Stub and Proxy, transaction and
   parcel shape, DTO field order and exceptions. Hand translated host interfaces
   do not establish generated transport behavior.
2. Preserve the observed optimized inspection boundary and inspect the remaining
   Settings read path, owner service publication and Binder implementation. The
   selected DEX definition check above is not instruction verification, a complete
   runtime classpath check or an Android startup test.
3. Inspect the final Console manifest, alias and DEX after shrinking for the
   Activity, controller, Proxy and DTOs. Preserve the actual downstream system
   server reference trace. Do not add a broad Manager keep rule or newly retain
   dormant writer and release paths to make a check pass.
4. Preserve the emitted policy, context and normal neverallow results for this
   source epoch. Check their inclusion in the actual image and exercise the
   Console and foreign client cases on Android. Compiler controls are not runtime
   policy observations. Preserve the home and work neverallows. Find permission
   is not Binder caller authentication.
5. Bind the factory APK's actual image path, privileged metadata, package, sole
   UID and current signer set to the built image. A source path predicate or
   matching signer tokens alone does not prove that origin.

Disposable Android runtime qualification remains separate. It must distinguish
an unupdated factory copy from a data update with an independent factory record,
missing record and fallback cases, current signer mismatch and rotation history,
shared or foreign UID callers, service replacement while the old Binder lives,
and user removal or serial reuse. Exercise Binder parceling and policy denials,
secondary user refusal, incomplete versus empty state and absence of write, lease
or work registration effects. This checklist does not authorize protected key
access, use of a retained guest, personal account data access or UID release.

A report for one stage must not promote the others: source consistency, module
compilation, generated artifacts, final image correspondence and Android runtime
behavior are distinct gates. None is newly qualified by this checklist.
