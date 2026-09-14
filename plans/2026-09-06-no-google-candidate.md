# Historical connected networking candidate

**Status:** an opt-in direct-AOSP/WebView experiment supplied bounded networking
results and exposed incomplete CT delivery. It was not a supported release. The
[current architecture policy](../docs/architecture.md) governs subsequent work.

## Technical scope

The experimental derivative disabled automatic WebView field-trial fetch scheduling,
used an explicitly selected DNS probe name, and retained Android trust validation.
It did not replace general SafeMode recovery with an invented success result or
remove security consumers to make a capture quiet.

Source choices and package inputs remain in the [experiment definition](../experiments/webview/README.md).
Provider APK signatures, package/static-library relationships and actual installed
payloads must be checked before runtime networking conclusions.

## Result and follow-up

The bounded workload did not establish complete direct-client network compliance:
CT download failure remained a failure despite a quiet destination capture. A later
[public CT delivery comparison](2026-09-07-public-ct-runtime.md) addressed that path.
Conditional application behavior and supported-phone/release qualification remain
separate from a tested emulator workload.
