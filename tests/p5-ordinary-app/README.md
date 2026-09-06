# Disposable ordinary-app proof

Optional [P5](../../plans/2026-08-28-phase1-andrix-hello-aosp17.md#p5-a17--prove-the-ordinary-app-boundary)
fixture. Live build/runtime state belongs in [current work](../../plans/current.md),
not this recipe. Implementing or building it is not P5 runtime proof.

This self-targeting instrumentation APK uses public SDK/NDK 37 and ARM64 JNI.
It is not in `PRODUCT_PACKAGES`, requests no permissions or shared UID, and is
not privileged or platform-signed. It uses the existing disposable
`:dev.andrix.usr.certificate`; no new key is generated. Keep private keys on the
build host, outside Git and evidence. An `android_test` may be debuggable; the
probe never uses `run-as`, UiAutomation, shell-permission adoption or a debugger.

## Build and review

In the pinned ARM64-only AOSP lunch environment:

```sh
m AndrixP5OrdinaryApp
```

Review the actual APK manifest, public signer identity and packaged JNI ELF.
Require the non-platform proof signer, only ARM64 JNI, Android linker/Bionic
ABI, and no permissions or privileged installation. The host runner pins APK
bytes; it does not independently attest the APK's source or signing provenance.

The valid-executable control is the **exact P3 image's** `/system/bin/sh`,
not a replacement for P2/P4 `andrix-hello` or an owner-userland design. Supply
the P3 artifact that this path resolves to, not a new device pull used as its
own oracle. The current r1 image stores the ELF directly as `system/bin/sh`.
The host and app both compare its SHA-256.

## Authorized runtime fixture only

Require reviewed P3/P4 provenance, unlocked user 0, an exclusive device lease,
and the controlled egress fixture. This runner does not launch/connect a VM,
root/unroot adbd, change policy, grant permissions, clear logs or manage capture.
Every device command selects the explicit serial. Root adbd is refused.

```sh
export ANDROID_SERIAL='EXPLICIT_AUTHORIZED_INSTANCE'
export ANDRIX_EXPECTED_FINGERPRINT='EXACT_P3_IMAGE_FINGERPRINT'
python3 scripts/proof/ordinary_app.py \
  --apk /absolute/build/output/AndrixP5OrdinaryApp.apk \
  --system-sh /absolute/extracted-P3/system/bin/sh \
  --aapt2 /absolute/pinned/build/host/bin/aapt2 \
  --evidence /absolute/outside/source/NEW-p5-evidence
```

Requires Python 3.9+, `adb` and the pinned `aapt2`. The runner refuses a
pre-existing proof package in **any** user, including retained-data uninstalls.
It installs with `-t --user 0`, without replacement or grants, and requires an
ordinary Package Manager UID and a byte-identical APK under `/data/app`.
Instrumentation launches an ordinary app process; shell commands never perform
the proof execs on its behalf.

JNI records UID/GID, SELinux identity, effective capabilities, Android
linker/Bionic mappings and page size. It runs `/system/bin/sh -c 'exit 0'` with a
fixed minimal environment, requiring successful exec and exit 0. It then:

1. Makes a fresh app-private directory/file, copies that executable, chmods it
   `0700`, and closes the writable fd to exclude `ETXTBSY`.
2. Verifies ownership, modes and every byte; rejects a `noexec` mount without
   changing it.
3. Forks/execs the copy with the same arguments/environment. Requires **EACCES
   from execve itself**, not a generic failure, loader exit, signal or timeout.
4. Rechecks bytes and file identity and removes only its fresh temporary files.

The child uses only async-signal-safe operations, an error pipe and `_exit`.
CLOEXEC distinguishes an exec error from a loader/program exit. Waiting and
reaping are bounded; child stdio is `/dev/null`, so loader diagnostics are not
captured and a nonzero control exit cannot pass. The host requires matching
Java/PM/JNI UID, ordinary `untrusted_app` with MLS categories, zero capabilities,
correct mappings and unchanged boot/fingerprint/ABI/page-size/shell hashes.

Only an acknowledged install with established APK/UID/path identity can be
uninstalled, after rechecking the same target. Lost acknowledgements, unknown
identity, changed boot/package or cleanup failure leave a FAIL and evidence for
operator reconciliation; there is no blind uninstall, `pm clear` or recursive
remote deletion. A PASS requires verified cleanup too.

Evidence retains APK/hash, source-shell hash, target facts, numbered command
argv/stdout/stderr/status (including timed-out output), native report and summary.
Do not edit it. This is one app/path/executable boundary, not all writable paths
or all app APIs. EACCES with DAC/noexec confounds excluded does not by itself
identify a particular SELinux rule; correlate expected AVCs and pinned policy
separately. This fixture does not prove runtime networking, P4, or owner execution.

## Host-only regression tests

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p test_ordinary_app.py
```

Synthetic parser/ELF/lifecycle tests block subprocess execution. They are not
native execution, artifact or runtime evidence. Compile and run the actual APK
on the authorized fixture before claiming P5; preserve failures rather than
relaxing its checks.
