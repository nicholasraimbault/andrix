# Keep notification and failure controls

**Status:** owner-controlled notification blocking and locked Stop passed their
listed bounded emulator controls. Keep remains off by default.

## Corrected image result

The optional Keep channel is explicitly blockable through Android's normal settings
using `NotificationChannel.setBlockable(true)`. Other system channels, permissions,
LOW importance, native binaries and lifecycle authority remain unchanged.

Observed controls covered active blocking ending work, a refused admission while
blocked, blocked-state persistence across reboot, re-enabling without automatic work,
fresh explicit Keep, and locked Stop with Console absent. An additional postboot
button click did not establish a completed admission request and is not a separate
denial pass. The blocked-start diagnostic remains generic rather than explaining
notification availability precisely.

Android's lockscreen visibility settings apply. The quiet notice is hidden when the
owner hides silent notifications. Locked Stop was exercised with silent notices
visible and sensitive content still hidden; the feature does not override that choice
or grant terminal access while locked.

## Test-driver freshness defect

A successful `uiautomator` process exit does not prove a fresh hierarchy was written.
Use a new output path and require the exact successful acknowledgement before reading
it. Do not reuse old XML after an error. Staging must select the intended consumer
source, not merely compute a checksum of whichever script happened to be copied.

The audit narrowed an earlier readiness claim without discarding independently
supported later input/output observations. See [reusable queue instructions](../scripts/proof/ui_queue.md).
Detailed transcripts and individual attempts are private operator evidence.

## Remaining decision

The owner approved [two fixed lab lifecycle fault controls](2026-09-14-lab-lifecycle-faults.md)
for actual primary-user CE locking and one finite delayed genuine snapshot reply.
They must be absent from normal images and must not add a general storage permission,
synthetic availability or key-withdrawal cleanup barrier. Android runtime qualification
of those controls is still pending.

Independent backend failure, broad pressure/suspend, phone and release behavior remain
outside the demonstrated scope. See [Keep behavior](../owner/keep/README.md).
