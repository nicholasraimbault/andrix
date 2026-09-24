# Native principals in Android policy

Status: proposal for review, not accepted mechanism or new runtime qualification. This refines
the [account contract](2026-09-21-android-unix-accounts.md) and
[accepted architecture](../docs/architecture.md#authority-identity-and-state). Android remains
the platform. The companion [composition contract](2026-09-24-owner-composition-contract.md)
separates ordinary principals from installation authority.

## 1. Capability and identity

An owner can execute ordinary native programs directly. Execution does not require an APK,
package registration, a platform signature or a separate security principal for each binary.
Programs deliberately sharing a Unix login identity share its ordinary authority. A work
scope accounts for lifetime and resources; it is not automatically a security sandbox.

Native programs must also have a coherent way to use Android capabilities without becoming
root or impersonating a foreground APK. The OS must know whose policy applies, whose consent
is required, whose data is involved and who should be shown as using the capability.

| Identity | Meaning |
| --- | --- |
| Android user and incarnation | The platform account to which work belongs. A recycled numeric user ID must not revive an old principal or grant. |
| Ordinary Unix login principal | The user's normal native execution identity, home and shared authority. Its complete credentials and MAC context are established before code runs. |
| Optional restricted principal | An explicitly isolated service or untrusted workload with separately enforceable authority. A name, changed HOME or another cgroup under the same broad credentials is not that boundary. |
| Android policy subject | The identity the authoritative permission, attribution, network, power and accounting services recognize for an operation. Its binding to the native principal cannot be supplied by the payload. |
| Work instance | One admitted execution and its descendants, bound to a principal, launch context and relevant user/CE epoch. A work ID is not an Android permission grant. |
| APK identity | Android's actual package, signer, UID and user relationship. Installing an APK does not appoint it a Unix login or platform administrator. |
| Administrative authority | A separate deliberate grant to establish an administrative context, including general root commands or a shell. Ordinary grants cannot manufacture it. |

Labels and code provenance can explain an operation, but an executable path, digest, package
name string or PID alone does not authenticate its principal. Shared credentials must not be
presented as separate security identities merely because the UI displays different programs.

## 2. State and responsibility

Android user and credential services own user existence and genuine CE availability. The
integration maintains a validated native principal binding to that authority, not a second
account system. The exact UID allocation and representation remain open.

Android's permission and policy authorities own applicable grants, revocation, attribution,
network policy and accounting. Any new native principal support must extend those authorities
or integrate through an explicit supported contract. A second consent boolean in a native
daemon must not override an Android denial. Auxiliary mapping or operation records are
legitimate when their owner and reconciliation rule are defined.

Andrix owns work admission, launch, Stop and its declared resource classes. The launch path
establishes the whole execution context before running owner code. Android supervises the
outer environment. Console and editors are clients, not lifetime owners of all native work.

A native Android API binding may mediate calls, but it must preserve the actual requesting
subject and applicable delegation. The target must not see only a permanently privileged
broker while attribution and revocation are maintained in an unrelated private database.
Physical process placement is not the contract.

## 3. Ordinary entry, grants and delegation

Grant checks bind the authenticated caller, Android user, native principal, requested effect
and current policy. Use kernel/platform caller identity and validated delegation, not supplied
UIDs or a caller chosen attribution label. An adapter must not run payload code with its own
service authority to make an otherwise denied operation succeed.

A stable login principal can have persistent grants, just as account state can persist across
work instances. This does not make a request already in progress valid after its execution or
user authority ended. Optional restricted principals need real isolation and independent grant
scopes; not every script is forced into one. Credential sharing and authority sharing must be
clear to the owner rather than hidden behind separate permission displays for programs sharing one identity.

An editor APK can receive explicit file access without receiving a Unix login. If the owner
wants it to submit ordinary native work, that is a distinct delegation with a defined user,
principal, operation scope and lifetime. The binding must follow Android's actual caller and
package identity. Reinstallation, identity reuse and application updates need declared
continuity rules; a cached package name is insufficient. Delegation to ordinary work grants
neither root nor installation signing. Revoking a client's ability to submit new work does
not itself cancel already accepted owner work; Stop is a separate authenticated effect.
Revocation of a capability used by that work follows the capability's declared rules.

Permission UI, privacy indicators and accounting should identify the real policy subject and
any meaningful delegation. They must not misleadingly attribute arbitrary native activity to
Console or to a trusted system service. Program descriptions are useful display metadata, not
a substitute for identity. These requirements do not authorize recording raw commands,
environments or sensitive contents by default.

Use stable public Android interfaces and maintained, versioned native bindings where possible.
An interface absent from the public NDK may need deliberate framework integration. Ordinary
programs should not each depend on private framework internals just to use routine phone
capabilities. An owner may still experiment with unsupported interfaces, with the compatibility
claim made explicit.

## 4. Lifecycle and revocation

- Account switching and screen relock do not by themselves establish CE withdrawal or Stop.
  User stop, deletion, actual credential withdrawal and resource termination are distinct.
- New admission and sensitive effects revalidate the relevant principal and user/CE authority.
  An earlier positive result cannot revive a stopped request or authorize a replacement user.
- Deletion closes old admission before identity reuse. Persisted grants and references must
  not attach to a recreated account or a new principal with the same displayed name.
- Revocation prevents new use under the revoked grant. Each Android capability must also state
  what happens to an existing stream, descriptor or accepted operation. Where immediate
  termination is required, the integration must actually provide it rather than advertise a
  policy flag as completion. Already returned data cannot be recalled.
- Cancellation and loss of a caller do not fabricate operation retirement. Retain ownership of
  accepted effects until their actual result and cleanup are known. Unknown replies are queried
  or reconciled under the same identity, not submitted again automatically.
- Restoring CE availability can permit fresh work under current policy. Old work or delegation
  tokens do not silently bind to the new epoch. Persistent policy and live use authority remain
  different objects.

## 5. Phone policy is part of the principal contract

| Surface | Required behavior to establish |
| --- | --- |
| Protected Android capabilities | Relevant runtime permission and AppOps decisions apply to the actual principal, with correct grant/revoke behavior and privacy attribution. |
| Notifications and interactive access | Use an attributed Android presentation path. Loss of UI access does not imply every detached computation must die. |
| VPN, firewall and data saver | The intended user's and principal's policy applies to actual traffic. Do not infer this from a home path, UI label or the existence of a Unix UID. |
| Doze, wake and background execution | Work retention adds no wake, network exposure or policy exemption beyond the principal's grants. No fake foreground state or blanket exemption used to evade phone policy. |
| Memory pressure, scheduling and thermal limits | Ordinary work has a defined importance/resource class integrated with Android supervision and phone priorities. A separate process manager does not make memory or battery free. |
| Battery and resource accounting | Attribute real use to the correct principal and user, including mediated operations. Do not charge unrelated apps to conceal native work. |

A supported default should preserve essential phone functions while allowing useful work.
Owners can deliberately authorize different policies or general administration, but unsafe
choices change which guarantees remain substantiated. Prototype quotas are not product limits.
Ordinary owner outbound networking, controlled listeners and isolated job network grants retain
their [accepted distinctions](../docs/architecture.md#lifecycle-and-networking).

## 6. Mechanisms to compare

| Candidate | Question it must answer |
| --- | --- |
| Android recognized principal/package association | Can a durable native subject use existing policy machinery without coupling its processes to an APK's UI lifecycle or requiring a package per executable? |
| Explicit framework native principal support | Which authoritative services must understand the subject, and how are grant, UID, lifecycle and update contracts kept coherent without unnecessary framework duplication? |
| Mediation through Android backed services | Can the target enforce the actual native subject/delegation and revocation, with correct accounting and policy, rather than lending a broker's standing privileges? |

These can be combined where justified. None is selected. A broker is not intrinsically wrong,
and a framework modification is not intrinsically a hack. The decisive condition is a coherent
identity and authority contract that can be carried across Android releases. The
[source comparison](2026-09-24-integration-mechanism-assessment.md) begins separating the
representation, binding and lifetime mechanisms against actual framework checks.

## 7. Deciding tests and open choices

Existing ordinary native execution, CE and work supervision proofs do not establish all the
policy surfaces above. Compare candidates using a small set of explicit cases:

1. An ordinary native program uses one useful Android capability, such as location or an
   attributed notification. Observe the actual grant, denial, attribution and revocation path.
2. Two programs deliberately sharing a login share its ordinary authority. A separately isolated
   sibling does not borrow a grant. An APK cannot claim either identity by supplying a label.
3. Repeat under a secondary Android user. Test actual VPN/network policy and background/power
   behavior with live positives, not only expected denials. Physical behavior has a separate gate.
4. Switch, stop, withdraw/regrant CE, delete and recreate the user while work and references exist.
   Show which policy persists, which live authority ends and why stale references fail.
5. Grant an editor file access and ordinary work submission separately. Revoke them independently;
   verify no implied elevation, cross-user access or service credential borrowing.
6. Carry the chosen integration across an upstream change. Measure which interfaces and policy
   assumptions require adaptation rather than declaring the first working representation stable.

Open consequential choices are the principal representation, useful capability/API coverage,
grant and delegation granularity/defaults, and the exact mobile resource policy. Choose them
against owner workflows and these tests. First class native programming remains the requirement;
this proposal neither claims it delivered nor lowers the goal because mechanisms are pending.
