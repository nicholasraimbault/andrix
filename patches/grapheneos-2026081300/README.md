# Opt-in owner-session policy integration

This is **one new, digest-guarded private-policy bridge**, not the preserved old
18-file AOSP patch series. It applies only to `system/sepolicy` at the pinned
GrapheneOS `2026081300` revision recorded in `owner-session-policy.json`.

The real policy compiler rejected a direct coordinator → app-workload transition:
Android reserves those transitions for its existing launchers. The accepted
Andrix design introduces a separate native owner identity; it must not borrow
root/shell identity or broaden ordinary APK execution. The bridge makes that new
boundary explicit rather than disabling neverallow checks.

Under `andrix_owner_session=true` only, it:

1. Declares the two private Andrix process types; the owner worker receives the
   existing app-workload policy class. No public/vendor policy API is added.
2. Excludes **only the new owner target** from the existing launcher assertion.
3. Adds a separate assertion restricting that target to **only `andrixd`**.

The implementation's exact allow rule remains in Andrix system_ext policy.
No existing domain is exempted, no existing allow rule is widened, and no ordinary
APK receives the owner UID/domain, home access or execution rights. With the flag
off, the new declarations/exception are absent. Vanadium and upstream framework
code remain unchanged. The worker-only syscall restriction separately prevents
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
