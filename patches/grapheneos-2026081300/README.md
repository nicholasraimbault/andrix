# Pinned Android source integration

Each adaptation has an exact source profile, a narrow patch and a dedicated inspector.
These are deliberate Andrix integration inputs, not permission to accept arbitrary changes
in an upstream checkout.

## Framework companions

`owner-lifecycle.*` integrates genuine CE authority observation. Use
`scripts/proof/android_lifecycle.py` to check, apply or revert its exact files.

`package-verity.*` makes restored APK file verification setup idempotent while leaving the
subsequent signature and digest checks in place. Use `scripts/proof/package_verity.py`.
See the [restoration design](../../plans/2026-09-22-package-verity-restoration.md) and
[exact method tests](../../tests/staged-apk-verity/README.md).

`package-installer-payload-sync.*` is ordered after package verity on the same Package
Installer file. It adds one checked fsync of the reverse mode target descriptor after a
successful copy, before the write can report success. Use
`scripts/proof/package_installer_payload_sync.py`. Its candidate is derived from the pinned
upstream through the exact package verity candidate, then its own exact patch. Apply refuses
unless package verity is applied; revert removes only this companion. The package verity
inspector recognizes the combined bytes as applied, keeps them when applying, and refuses
to revert until the companion is removed. Its `--require-adapted` means the verity
correction is present, alone or in the exact combination, and does not require this
companion. The companion's own `--require-adapted` requires the combination, so a build
that wants both requires both. Each report names every component with its state and
profile hash. The patch is byte identical to the
[host tested candidate](../../tests/installer-durability/pis-reverse-write-sync.md).
Qualification is host only, and the companion is not Android qualified. It does not cover
directory entries, renames, settings or whole install durability. Android compilation and
runtime are separate gates.

`native-principal-pins.*` adds the internal Package Manager reservation component for native
account identity lifetime. Use `scripts/proof/native_principal_pins.py`. The
[implementation and limits](../../owner/platform/principal-pins.md) distinguish checked settings
persistence and allocator fencing from the still disabled native account/factory path. Its one
boot read constructs the version 2 store format, `Format.V2`, as the
[version 2 normal store plan](../../plans/2026-10-02-native-store-v2-normal.md) describes. The
production format guard in `scripts/proof/native_creation_binding.py` reads every patch here per
file section. It requires that one anchored construction and refuses `Format.V1` in any of them.
A checkout that still holds the earlier adapted bytes, with the version 1 boot literal, is refused
as unknown bytes. It needs a revert with the earlier tools or a reviewed manual repair.

`native-identity-writer.*` is a separate lab test adaptation. It adds one fixed subject writer
route to the package shell and the [test helper](../../tests/native-identity/writer/README.md).
Normal framework admission rejects its adapted or partial state. The dedicated
`scripts/proof/native_identity_writer.py` requires explicit lab scope for apply/revert and
build admission. The shared framework fence makes the lab admission decision for every tool that
inspects with it. It requires the complete stack: the native principal companion, the owner
lifecycle CE companion, and package verity with its payload sync companion, each exactly adapted.
It accepts the fixture exactly upstream or exactly adapted, so a partial fixture refuses every
inspection, check, apply and revert. The writer tool also requires the fixture exactly upstream
before an apply and exactly adapted before a revert, so a repeated apply or revert refuses. This
does not enable the native execution factory. Reverse this fixture before reversing the native
principal companion.

The earlier lab native store format token changed the boot literal to `Format.V2` in a marked lab
image only. It is retired, because the normal image now constructs `Format.V2` itself. Its tool,
tests, profile and patch stay in Git history and in the sealed records of the `23cede6` lab build.

All framework inspectors check the complete known change set. Recognizing the companion
requires its exact original or candidate bytes. Unknown changes, staged changes and
unrelated files are refused. Build preparation must require the adaptations it uses, not
infer their presence from a successful check of a different companion.

## Native owner policy bridge

This is one digest guarded private policy bridge, not the preserved old 18 file AOSP
patch series. It applies only to `system/sepolicy` at the pinned GrapheneOS `2026081300`
revision recorded in `owner-session-policy.json`.

This policy bridge describes the existing reserved UID vehicle. The newer ordinary principal
entry is a separate inactive implementation and has not replaced these roles or their Binder
denial.

The policy compiler correctly rejected trusted-daemon execution of writable data.
An initial app-workload approach then ran into Android's launcher and inherited
zygote/run-as rules. Andrix is instead adding the distinct **native owner** tier
from the accepted architecture, without borrowing an APK, zygote, run-as or shell
identity. The bridge explicitly defines that new boundary.

Under `andrix_owner_session=true` only, it:

1. Declares three private Andrix types: coordinator, native owner and own-home data.
   The owner is **not `appdomain`**. No public/vendor policy API is added.
2. Excludes only the new owner from the two assertions prohibiting native-domain
   writable-data execution, then asserts that **only its own home type** may be
   executable data and no other domain may execute that home type.
3. Restricts entry to an exec transition from only `andrixd`, with no dynamic
   transition into the owner domain.
4. Removes only the new owner from broad non-app cgroup-write rules. Its fixed
   init-owned resource limits must not be changed or escaped by owner code.

Exact per-file allow rules remain in Andrix system_ext policy. No existing domain
is exempted or granted new permissions; ordinary APKs receive no owner identity,
home access or execution rights. With the flag off, the new declarations and
exceptions are absent. Vanadium, framework code and vold's key-management/status
authority remain unchanged. The worker-only syscall restriction separately blocks
ambient Binder authority from the reserved Unix UID.

Use `scripts/proof/owner_policy.py --source-root SOURCE --action apply --evidence
NEW_EXTERNAL_JSON` after reviewing the exact source and delta. `check` recognizes
only original or exact adapted bytes, verifies the pinned project HEAD and rejects
staged/other tracked changes. `revert` restores only those exact original bytes;
no Git reset, clean filter or global configuration change is used. The helper
reuses the callback-disabled source-verifier Git execution profile.

This adaptation means the base's all-project *tracked-clean* result no longer
applies unchanged to that project. Keep the unchanged manifest HEAD and this
explicit file/patch receipt separate; use the dedicated check for the adapted
project. Rebase deliberately if upstream bytes change. Compilation and runtime
qualification remain necessary. This source bridge alone is not a security PASS.
