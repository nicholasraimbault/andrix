# Owner authority, signing and recovery

Status: accepted ownership requirements under the
[vision revision](2026-09-21-owner-composable-android.md). Mechanisms and provisioning are
unimplemented proposals, not new runtime permissions or signing authorization.

## Contract

Daily Unix work and APKs run without administrative authority. An authorized device
administrator can deliberately run general root commands, including a root shell. The
interface must not be limited to a curated menu of installation/remount actions. It also
must not make the daily user or every owner signed app permanently privileged.

The trusted path authenticates the authorization, constructs a complete administrative
execution context and accounts for its lifetime. Arbitrary command execution is available
within the authorized context; partially privileged bootstrap operations are not exposed
as independent gadgets. Ordinary work submission cannot select that context on its own.
The exact authorization UI, credential requirements, duration and process arrangement need
source review, threat analysis and tests.

## Two distinct trust relationships

Andrix distribution signatures establish provenance. Individual owners control the trust
and deployment authority of their installations. No universal private platform key is
shared with all owners, and local ownership must not require the project to approve each
modification.

An initial installation personalized with owner signing keys is a candidate starting model.
It is not yet proof that an existing installation can be rekeyed live without data loss.
Review APK certificate continuity, shared UIDs, privileged permissions, SELinux labeling,
APEX payload/container keys, boot verification, OTA verification and vendor trust separately.
Preserve third party application identities rather than indiscriminately resigning them.

On-device component signing is a goal, but platform private material must not be silently
available to ordinary programs in the home directory. A protected signing facility with
explicit owner authorization is a candidate. Key custody, exportability, backup, recovery
when the device cannot boot and compatibility with later locked operation remain open.
Protecting keys does not mean making the owner dependent on an unavailable vendor service.

## Update and failure behavior

- Verify distribution provenance independently of authorization to deploy a personal build.
- Preserve the owner's selected signing identities across compatible updates; do not claim
  stock update artifacts automatically work after personalization.
- Refuse incomplete or inconsistent trust transitions. A package install success is not a
  complete key migration or boot recovery result.
- Record significant authority changes under the accepted minimal diagnostics policy,
  without automatically capturing root shell arguments, environments or output.
- Keep a deliberately tested recovery route. Hardware protected or nonexportable keys do
  not automatically provide a backup or replacement device migration mechanism.

A device administrator can alter the OS itself. Ordinary account isolation remains required,
but protection against an actively malicious platform administrator is not promised. Root
access also does not establish that another locked account's CE keys are available.

## Verification sequence

First inspect the selected Android source, platform package relationships and supported
hardware trust mechanisms. Compare a protected signing/elevation facility with host assisted
personal builds and an initial personalization workflow. Select mechanisms only with an
explicit rationale and recovery plan.

Use the [workshop component proof](2026-09-21-workshop-components.md) to test narrow parts
without relabelling a host controlled action as a finished native elevation interface.
Later test wrong user, wrong package/signer, denied consent, cancellation, replay, session
loss and interrupted installation, plus successful arbitrary administrative commands.
Unrelated work and ordinary APK boundaries must remain intact. Physical trust/key recovery
needs the separate [Pixel gate](2026-09-21-pixel-integration.md).
