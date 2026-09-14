# Android UI on the emulator foundation

**Status:** normal setup rendering/navigation was exercised without credential,
permission, hidden-API or screenshot-protection bypasses. Later foundation tests
completed ordinary onboarding.

## Technical finding

An emulator-profile Bluetooth expectation did not match the selected GrapheneOS
configuration. The correction scoped that expectation to the emulator product,
without enabling the radio or removing Android Bluetooth services. A working image
must satisfy the actual boot monitor as well as render a frame.

## Limits and follow-up

A rendered setup page is not complete phone/UI qualification. Preserve normal
credential entry, foreground/input authority and Android capture policy. Broad
IME/accessibility, hardware and power behavior remain separate tests.

See the [connected foundation result](2026-09-09-grapheneos-connected-baseline.md)
and [owner terminal](2026-09-10-owner-tools.md).
