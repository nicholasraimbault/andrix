# Opt-in native owner policy integration

This is **one new, digest-guarded private-policy bridge**, not the preserved old
18-file AOSP patch series. It applies only to `system/sepolicy` at the pinned
GrapheneOS `2026081300` revision recorded in `owner-session-policy.json`.

The policy compiler correctly rejected trusted-daemon execution of writable data.
An initial app-workload approach then ran into Android's launcher and inherited
zygote/run-as rules. Andrix is instead adding the distinct **native owner** tier
from the accepted architecture—not borrowing an APK, zygote, run-as or shell
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
qualification remain necessary—this source bridge alone is not a security PASS.
