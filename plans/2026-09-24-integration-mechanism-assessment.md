# Integration mechanisms: identities, trust and selection

Status: source investigation and proposed experiments. This compares mechanisms against the
[native principal](2026-09-24-native-principal-contract.md) and
[owner composition](2026-09-24-owner-composition-contract.md) drafts. It does not select a
production representation, signing topology or update mechanism. No runtime, key, installation
or device operation has been performed or qualified by this assessment.

## Source scope

The observations below use exact committed, unchanged files from the existing foundation:

| Repository | Revision |
| --- | --- |
| `frameworks/base` | `aab06a8bd44c4c2b58eeec780fde83baa9d43a40` |
| `system/apex` | `ce2bb9f710183c864040401d859874b5723e44d8` |
| `system/update_engine` | `79f478a4f89e701e85fa15dec340bf445342abbd` |

Selected complete file copies were compared with their committed blobs before excerpts were
used. Existing CE and package verification adaptations remain separate; this is not a claim
that the entire framework tree is unmodified, or that these source revisions alone identify
the previously qualified images. Source branches, feature flags and runtime policy still need
actual target checks.

## 1. Native identity is more than assigning a Unix UID

The inspected paths already distinguish a numeric UID, a package association and permission
or operation policy. A process need not become a UI process merely to have a recognized policy
subject, but that independence is a requirement to prove, not an existing integration pass.

Paths in this table are relative to `frameworks/base`:

| Source | Observation | Consequence for the candidates |
| --- | --- | --- |
| `services/permission/java/com/android/server/permission/access/permission/PermissionService.kt:569–644` | `checkUidPermission` first checks the Android user, then consults package based permission state when a package is found. Its fallback uses `SystemConfig.systemPermissions` keyed by the full UID. | A configured native UID can have fixed permissions, but that is not the package based runtime grant and consent path. A grant alone does not satisfy other services' caller checks. |
| `services/core/java/com/android/server/notification/NotificationManagerService.java:10150–10178,13549–13563` | Normal notification resolution requires the package to belong to the actual caller, or an explicitly allowed delegate relationship. Root/system/phone exceptions are distinct paths. | Passing a package name string is insufficient. A privileged service posting under its own exemption would not prove ordinary native participation. Existing notification delegation is a mechanism worth examining, not a complete principal model. |
| `services/core/java/com/android/server/notification/PermissionHelper.java:60,77–84`; `NotificationManagerService.java:10303–10318,10363–10365` | Notification policy consults `POST_NOTIFICATIONS` for the resolved UID. Blocking also has channel and notification category behavior. | A properly designed notification test can establish its own permission path, not merely package recognition. Use an ordinary notification, not a media/call or foreground service exception, and observe actual posting rather than treating an API return as delivery. |
| `services/core/java/com/android/server/appop/AppOpsService.java:5121–5231,7638–7655` | AppOps validates UID/package ownership, has explicit root/static system exceptions, validates attribution tags and finally compares the resolved package UID with the subject UID. | Fixed system exceptions are not a general ordinary principal interface. A supplied tag does not authenticate a principal; mediation still needs a subject the target recognizes. |
| `core/java/android/content/AttributionSource.java:343–368,497–501` | Caller UID enforcement and registered attribution tokens are distinct checks. | An attribution chain is not itself a permission grant or a reason to trust a caller supplied identity. |
| `location/java/android/location/util/identity/CallerIdentity.java:79–124` | The checked Binder constructor verifies the claimed package against `getPackagesForUid` for the actual Binder UID. The unsafe constructor documents that another check must validate the package. | A language binding or proxy must preserve a valid subject, not choose the unsafe helper as an authority shortcut. |
| `services/core/java/com/android/server/location/injector/LocationPermissionsHelper.java:94–110` | Location access combines the permission check with an AppOps check for the caller identity. | Permission assignment alone is not location access. This excerpt does not establish foreground, background or complete revocation behavior. |
| `services/core/java/com/android/server/connectivity/Vpn.java:1887–1994` | Default ranges include the user's UID range. App allow/deny lists are converted from package names to UIDs; eligible application UIDs also add SDK sandbox UIDs. | It is incorrect to infer that every native UID automatically escapes a VPN. User mapping and package list behavior are separate questions. Actual routing and lockdown enforcement still need testing. |
| `core/java/android/os/UserHandle.java:321–326,414–440` | User ID and app ID are encoded in UID arithmetic. | A HOME directory does not select the Android user. This arithmetic is not, by itself, a complete account incarnation or policy subject contract. |

These observations support three separate design axes:

1. **Representation:** how Android recognizes the native principal and owns its grants.
2. **API binding:** how an ordinary program reaches a useful Android capability and preserves
   attribution. This may be direct IPC or a helper operating under the same principal, or an
   explicitly delegated service. A language bridge need not be a privilege bridge.
3. **Execution and lifetime:** who launches and supervises work, updates its resource importance
   and handles user/CE withdrawal. Neither a package association nor an API proxy settles this.

A mediator therefore does not eliminate the representation question. Conversely, associating
with a package does not require coupling every native process to that package's UI lifecycle.
Those implications must be tested rather than built into the terminology.

### Candidate comparison

| Candidate | What it may reuse | Main unresolved obligation |
| --- | --- | --- |
| Deliberate Android principal/package association | Package lookup, UID permission state, notification channels/delegation and package based policy UI | Stable principal registration and deletion, consent entry, process importance and policy attribution without a resident dummy app or a package per executable |
| Explicit native principal support in the framework | Android's policy authorities extended to understand the new subject | A complete integration surface across permission, AppOps, UI, networking and resource services, with measured upstream maintenance cost |
| Android backed mediation | Existing service delegation or attribution machinery where it actually applies | The target must enforce the intended principal and current grant. A broker's own broad grants are not an acceptable substitute |

These are combinable, not three mutually exclusive complete systems. The proposed first
comparison should use an ordinary principal association as a reference case because these
services already consume that relationship. This is not selection of an APK wrapper as the
product architecture. If it cannot meet lifecycle or identity continuity requirements cleanly,
explicit framework support remains a legitimate candidate.

## 2. Platform trust is not one certificate comparison

A managed component has several relationships: artifact provenance, accepted package identity,
privilege and MAC assignment, containing object trust, and deployment/boot authorization.
Adding an owner key to one check does not satisfy the others.

Framework paths below are relative to `frameworks/base`:

| Source | Observation | Consequence |
| --- | --- | --- |
| `services/core/java/com/android/server/pm/PackageManagerServiceUtils.java:478–564` | Package update compatibility checks signing capabilities against installed and disabled factory package state, followed by shared UID consistency. | A permission grant or detached owner approval does not already make an independently signed replacement acceptable. |
| `services/permission/java/com/android/server/permission/access/permission/AppIdPermissionPolicy.kt:1513–1558,1836–1894` | Signature permission relationships and protection flag grants are separate paths. Privileged, installer, preinstalled and known signer cases have their own conditions. | Platform privilege cannot be reduced to possession of one key. A known signer permission rule is not a universal package update or shared UID delegation mechanism. |
| `services/core/java/com/android/server/pm/SELinuxMMAC.java:619–637` | Certificate matching, including a supported rotation relationship, precedes package specific `seinfo` mapping. | Package installation and permission grants do not automatically establish the intended MAC identity. |
| `services/core/java/com/android/server/pm/InstallPackageHelper.java:4740–4748`; `ScanPackageUtils.java:1028–1072`; `core/java/android/util/apk/ApkSignatureVerifier.java:88–106` | System partition scan can collect certificate information without full APK verification under its trusted partition assumption. The verifier explicitly warns that this is unsafe outside an already trusted input. | The authenticated image is itself a trust boundary. Factory scanning and ordinary data APK installation are not interchangeable paths. This is not a proposal to forge signer metadata or skip artifact verification. |
| `services/core/java/com/android/server/pm/ReconcilePackageUtils.java:250–303` | System image reconciliation has a signing change path that retains data, with consistency requirements for the shared UID set and hard failure cases. | Universal claims that every signer change necessarily wipes all data are too strong. This code is not a qualified, lossless rekeying procedure. |
| `system/apex/apexd/apex_file_repository.cpp:419–440`; `apexd.cpp:1143–1160` | The APEX data selection path checks its bundled public key against the preinstalled APEX and rejects lower versions; equal versions are not rejected by that comparison. | APEX payload trust and ordering cannot simply inherit an ordinary system APK rule. Container, payload and nested APK relationships remain distinct. |
| `system/update_engine/payload_consumer/payload_verifier.cc:75–93,146–192` | The payload verifier builds a public key set from certificates and verifies payload signature data against it. | OTA payload authentication is a separate role. This sampled verifier does not establish provisioning, bootloader acceptance or recovery behavior. |

Owner control may be realized by personalizing selected roles, explicitly delegated trust, or
a role specific combination. The trusted factory image path is part of that comparison, not
an exception to ignore. The owner trust model, selected component representation and activation
mechanism must be chosen together coherently, but none logically forces all the others.

In particular, this source does not justify either of these shortcuts:

- A platform APK key is a universal installation key, so every object must be re-signed by it.
- An owner signed image makes all embedded metadata trustworthy for every future data update,
  so package, shared UID, MAC or artifact checks can be omitted.

The accepted portable recovery default and current protected signing policy remain unchanged.
Stronger claims against a compromised running OS require the separate signing trust boundary
in the proposed contract; these source observations do not supply hardware assurance.

## 3. Selection still needs an explicit owner contract

`InstallPackageHelper.java:4644–4719` considers the path, version and shared user relationship
when reconciling a factory package with a data replacement. `PackageVerityExt.java:104–126`
rejects a normal system APK data update that is not strictly newer than its factory package;
static shared libraries have a distinct equality rule. `StagingManager.java:649–659` rejects
restored staged sessions when the platform upgrade changes their prior assumptions.

These are existing native mechanisms, not owner selection semantics. A larger local number
cannot establish which upstream fixes or owner changes are present. An image update does not
by itself prove a data override was displaced. A retained planner record cannot declare the
new code active if native state selected something else.

Compare coordinated factory/data deployment codes, explicit managed selection and coherent
image realizations against the same cases. Do not forbid valid external intent records, assume
an A/B update rolls back arbitrary data, or choose a new version encoding before the authority
and reconciliation contract is clear.

## 4. Proposed first experiments

### Native principal reference case

Use a disposable Android recognized principal and a separately supervised ordinary process.
Trusted setup resolves the intended user/package binding and constructs the complete launch
context. An ordinary caller cannot select arbitrary UIDs or service credentials. Establish
the real caller identity without a system/root exemption. The API binding may initially be a command/helper under that same
principal; qualify the binding language and interface separately rather than calling an ART
command a completed native C API.

Prove one useful capability, with notification posting a candidate first path:

- Deny before the applicable grant; allow after real platform grant and observe correct
  attribution. Record whether the test used actual owner consent UI or only privileged setup.
- Close the presentation app and observe the separately supervised process. Do not invent
  foreground state to keep access working.
- Revoke and establish the precise boundary for new and already accepted effects.
- Refuse a foreign UID/package claim and a deliberately isolated sibling without its own grant.
- Repeat under another full Android user, then test actual VPN/list policy and user stop/reuse.

A notification pass can establish the observed notification permission and posting path. It
does not establish location access, AppOps foreground behavior, privacy indicators for other
capabilities, Doze, battery attribution or phone reliability.

The deciding next case should request a location stream from the same ordinary subject
under a secondary user, with no resident APK UI process. Use a test provider where appropriate
and record the user's actual running/foreground state. Compare denial before grant, delivery
under an applicable background grant, correct AppOps/privacy attribution and revocation of
both new requests and a live stream. Refuse an unassociated UID claiming the package, the
wrong user's identity and an unrelated APK. A grant limited to foreground use is a deliberate boundary
case: diagnose the actual rejecting condition before attributing failure to process state.
If data arrives, establish the real foreground authority rather than accepting an unexplained
bypass. Record whether revocation kills the process or only ends access.

This is coverage to establish, not behavior inferred from package registration. Complete
user removal/reuse, SELinux access, traffic enforcement, Doze and battery accounting remain
separate gates. A raw fixed UID left in user 0 does not become another user's principal merely
because the process is pointed at that user's home; mapping identities for each user is still a design
choice, not an allocation selected here.

### Owner trust and selection reference case

For one SystemUI variant, first list each identity, privilege and containing artifact relation.
Compare its delivery as a data replacement and as part of a coherent image. Make explicit which
roles are personalized, retained or delegated and where each native check obtains its authority.
Use only disposable identities if a later execution plan is authorized.

The comparison must then carry the variant and upstream fixes across real source changes,
including a conflict, stale plan, old data override and recovery from a broken UI. A source
comparison comes before any migration claim. Measure rebuild/merge cost and native reconciliation
rather than treating a successful signature or an APK version increment as the result.

Each runtime experiment needs a bounded plan, exact inputs and actual resource admission.
This assessment authorizes no new platform permission shortcut, personal key provisioning,
verification toggle, unqualified identity transition or handset action.
