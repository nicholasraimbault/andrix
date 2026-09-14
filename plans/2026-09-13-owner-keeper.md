# Trusted owner-work lifecycle boundary

**Status:** groundwork superseded by [Android-owned integration](2026-09-13-android-lifecycle.md).
Public polling and keeper-process lifetime were not sufficient native key authority.
A universal synchronous pre-key-eviction cleanup barrier was not adopted.

## Separate requirements

- Owner consent to keep computation alive.
- Authoritative Android user/CE lifecycle, including revocation.
- Foreground/unlocked permission to read or send terminal input.
- Recovery of terminal/application presentation after client loss.

## Reusable findings

Availability needs operation/epoch provenance; stale cache or delayed replies cannot
bootstrap a fresh authority lease. Anchor freshness at query issue, not receipt.
Bind the native monitor to one platform Binder lifetime and reject replacement epochs.

Binder identity is not a supplied process number. Dynamic death-link cookies require
registration fencing and reclamation at `onUnlinked`, not immediately after unlink.
Actual cleanup still belongs to Android init's complete process group.

These requirements inform the implemented platform adapter. Source/host models remain
distinct from Android identity, key-operation and recovery controls.
