# Bounded native owner session

**Status:** the native owner identity, CE home, authenticated Console, PTY workflow,
ordinary-app isolation and whole-group cleanup were demonstrated in the emulator.
Later [Keep](2026-09-14-keep.md) adds explicit Console-independent work; plain sessions
retain their Console-bound lifetime.

## Design boundaries

- Native owner work uses the dedicated Android UID/SELinux role, not APK identity or
  root. The coordinator and worker share the Unix owner identity but have separate
  MAC roles; actual Binder UID/SID and object lifetime authorize operations.
- Android prepares credential-encrypted owner storage. The daemon must not create an
  unencrypted fallback or treat a directory policy/open descriptor as live key authority.
- The daemon owns the real PTY. Console receives a revocable framed stream, with
  foreground/unlocked checks and a bounded BOOTTIME lease.
- Init owns resource admission and complete cgroup cleanup, including descendants
  that detach from a Unix process group. No capability or worker cgroup-write grant
  is added to manufacture cleanup.
- No automatic work starts merely because the daemon starts or the device reboots.

## Reusable verification

Check the actual compiled policy, signer/package mapping, process role and inherited
resource bounds. Bracket ordinary-app negatives with live owner positives. Exercise
normal unlock, input, detach/return, relock, End and reboot. Keep source tests,
compiled artifacts, runtime controls and security claims distinct.

Factory APKs must not carry update-only signature sidecars. Use Android's normal
verified update path for development updates; do not relax PackageManager checks.

See [components and build flags](../owner/README.md), [policy bridge](../patches/grapheneos-2026081300/README.md)
and [Android lifecycle integration](2026-09-13-android-lifecycle.md).
