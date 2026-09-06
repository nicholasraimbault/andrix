# Offline ARM64 QEMU smoke

**Authorized and completed on 2026-09-06.** This additional functional test
runs the existing ARM64 image through QEMU CPU emulation on x86-64. It is not a
substitute for the [milestone](2026-08-28-phase1-andrix-hello-aosp17.md)'s native
ARM64/KVM or connected no-Google proof. The owner explicitly authorized this
bounded test before the remaining P3 endpoint review was complete.

## Exact inputs and execution

- Direct AOSP `android-17.0.0_r1`, with the previously recorded seven-file
  adaptation and overlay producer `9eb0bd462d63c86c37fe4cfddad764ab379e7d48`.
- Fresh copies of all 28 frozen image files, rehashed against their manifest.
- Matching x86 host package SHA-256:
  `1b89133063970c57419aa026343ce5681319b46d9e4a30a8deb58f8e3bfdc3a2`.
- Packaged `qemu-system-aarch64`, TCG, `cpu=max`, GICv2, four vCPUs,
  4096 MiB guest RAM and `guest_swiftshader` at 720×1280. No host desktop needed.
- Guest security enforcement enabled, metrics explicitly off, WebRTC off,
  private TAP interfaces, and an explicit private RIL DNS address.
- Rootless user/mount/PID/network namespaces with only the test files and
  necessary host tools/devices exposed. Project signing keys, credentials and
  the build tree were not mounted. No external network interface/default route
  or public host listener was added.
- The unmodified host capability helper came from `google/android-cuttlefish`
  commit `c546c02bfa7f5a257f4d5dc7b1c903a13620e7fd`. Scoped TAP/vsock capabilities
  were exercised separately; no fake `/manager.sock` or capability result was used.

Full packet capture began before assembly and remained active through the
checks and teardown. It recorded 30,441 packets with zero kernel-reported drops.
The namespace intentionally had **no Internet connectivity**. Failed/absent
network service responses are not successful DNS, NTP, TLS, CT or privacy tests.
The guest stopped at 21:48:06 UTC; the host's heavy-work lease was released.

## Observed results

| Check | Emulated result |
| --- | --- |
| Android boot | `sys.boot_completed=1`; Android 17 / API 37; lock screen rendered. |
| Identity | Expected `andrix.r1.9eb0bd4` fingerprint; sole ABI `arm64-v8a`. |
| APEX | Exact signed `dev.andrix.usr` container active as a factory APEX. |
| Payload | Both canonical APEX and `/usr` paths match the frozen ELF SHA-256, same device/inode, exact `andrix\n` output. |
| Filesystem | `/usr` is a read-only mount; `/etc -> /system/etc`; Android/Bionic ELF linkage retained. |
| SELinux | Enforcing throughout the checks; no guest policy, label or permission repair. |
| RKP controls | Endpoint empty and RKP-only false, as configured in the image. |
| Ordinary app | UID 10124, `untrusted_app`, zero effective capabilities; valid system-shell control executes; byte-identical app-private copy fails `execve` with **EACCES**. Verified uninstall. |

The guest kernel used 4096-byte pages. This does not qualify a 16 KiB host or
physical phone. The WebView provider remains the original 145 prebuilt; the
separate Vanadium APK experiment was not installed or promoted.

## Preserved failures and narrow repairs

The first assembly succeeded, but the local smoke guard incorrectly expected
one config file. r1 emits two identical assembly/per-instance copies; the guard
was corrected to require those exact paths and byte equality. Initial namespace
entry/cwd and a missing public `awk` alternative link were host setup errors,
not Android failures. The controller's explicit loopback ADB transport also
needed connection; the actual CVD transport was used for the proof commands.

The existing device checker exposed a real inspection-context difference:
`adb pull /usr/bin/andrix-hello` was denied directory search in the `adbd` SELinux
domain, while the ordinary `shell` domain could read and execute it. The checker
now streams the two fixed payload paths with `adb exec-out cat`, retains exact
ELF/hash checks, and appends a failure marker if the remote read fails. It does
not root adbd or broaden access. New regressions cover failed, partial, corrupt
and text-altered reads; all **146 host-only tests** pass.

A subsequent checker run correctly rejected earlier audit records from the
failed `adbd` read and the expected ordinary-app negative test. Complete logs
were saved, those records were classified, and the repaired device checks passed
in a fresh log window. The full earlier logs/capture remain preserved; this is
not a claim that the whole boot/test history contained no denials.

## Still unproved

Native ARM64/KVM execution, host/phone hardware behavior, connected endpoint
policy and no-Google traffic remain pending. Offline isolation cannot prove
network independence. This successful smoke test does not complete Phase 1,
create a Pixel product or constitute a supported OS release.
