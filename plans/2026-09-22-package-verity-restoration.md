# Idempotent file verification setup for restored APK sessions

Status: the local framework patch, exact method tests and guarded source cycle pass.
The corrected framework and matching selected image are built. Runtime remains to be
qualified.

## Observed problem

The [SystemUI component runtime](2026-09-22-systemui-component-runtime.md) completed its
finite controls but retained six session restoration errors. Package Installer tried to
enable fs-verity on an APK that was already protected before reboot. The kernel returned
`EEXIST`, and restoration failed to populate `PackageLite`. The existing installation path
then reparsed the package and completed the intended installation or rejection.

This is not a reason to suppress a warning globally or bypass verification. A restored
session should validate normally without first failing an operation whose desired state
already holds.

## Chosen correction

In `PackageInstallerSession.enableFsVerityToAddedApksWithIdsig`, retain the existing
sidecar requirement for setup, then query actual file verification state. Call setup only
when that state is not enabled. Continue accounting for protected APK bytes in either case.

The correction is local to this Package Installer path. `VerityUtils` keeps its existing
error contract for all callers. Inspection errors still return false from `hasFsverity`,
so setup is attempted and can fail. Other setup failures remain `PrepareFailure`; they are
not converted to success.

Validation still calls `getAddedApkLitesLocked` afterward. The V4 path measures the APK's
kernel digest, compares the signed hashing information and file length, and verifies the
signature. An existing file verification flag is not a substitute for those checks.
The higher level verifier returns an error for a present V4 signature that fails
verification. It falls back to older schemes only when that signature is not found.
Installed package signer/version requirements and the common staging policy stay unchanged.

## Ownership and alternatives

This check runs in the existing session validation path under `mLock`. The staging
directory is created by the system service with mode `0775` and its policy label. The
ordinary installer uses session operations, not unrestricted directory mutation. Existing
checks bind writes to the session owner and reject writes to a sealed session; sealing
also checks outstanding transfer descriptors.

Sealing alone is not claimed to atomically exclude every possible writer. In the inspected
source, some write checks and registration occur in separate locked regions. Kernel file
verification protects an already enabled inode, and subsequent signature/digest validation
is still required. The patch adds no new write, relabel, installer or capability authority.

Alternatives not chosen:

- Globally treating `EEXIST` as success in `VerityUtils` would change other callers' contract,
  including callers without Package Installer's subsequent verification.
- Suppressing restoration errors would preserve the broken validation path and fallback.
- Removing the sidecar or file verification requirement would weaken the intended checks.
- Adding a new general verification abstraction is unnecessary for this single local state
  transition. The source adapter remains narrow and pinned.

## Source integration

The patch and profile live under `patches/grapheneos-2026081300/package-verity.*`.
`package_verity.py` recognizes only exact upstream or candidate bytes. The existing CE
inspector now verifies this one known companion before accepting the complete framework
change set. It does not introduce a path exception for arbitrary changes, and either
adaptation can be checked independently without discarding the other's fence.

The original and candidate method fixtures retain source attribution and are checked
against their complete pinned source files. Host tests execute both exact method bodies,
including the upstream duplicate setup failure, successful repeated/restored setup,
missing sidecars, mixed batches and inspection/setup errors. These supplied state tests
are not kernel or cryptographic qualification.

## Qualification and remaining gate

Apply, inspect, revert and reapply passed against the actual pinned framework, with the
accepted CE changes preserved. The exact upstream method model failed on `EEXIST`; the
candidate model passed its restored/repeated and error cases. The host suite passed 475
checks, then 476 after adding the mismatched sidecar cause check.

The matching selected image compiled the corrected framework and passed 13 frozen native
controls. Inspection of the actual compiled Package Installer class found the existing
verification state branch skipping the setup call. The original factory SystemUI APK still
matched its byte identical version 37 baseline. The compiled SELinux policy is unchanged
from the previously qualified staging correction. Temporary init/LMKD adaptations were
restored; the two declared framework companions remain applied and fenced.

A scoped independent source review found no concrete bypass in the local change and
identified limits of the sealing argument. Primary review also checked the physical
staging directory setup and the higher level V4 error/fallback handling. These are source
findings, not runtime clearance.

The remaining gate is a fresh regression guest. Exercise A38 and good source restoration
R39, and require normal restored validation without the redundant enable error or missing
`PackageLite` fallback. Retain signer and missing sidecar controls, and add a deliberately
mismatched pair made from the existing A APK and R sidecar. A correct kernel flag alone
must not make an invalid pair or unauthorized signer acceptable.

No live policy patch, global error suppression or change to ordinary user authority is part
of this correction. The completed earlier component proof and its warnings remain intact.
