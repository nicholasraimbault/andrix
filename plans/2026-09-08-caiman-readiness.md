# Pixel / caiman readiness

**Status:** physical-device integration remains unqualified. There is no buildable
Andrix Pixel deployment product in this repository, and emulator success is not
permission to unlock or flash a handset.

## Required product inputs

A physical target needs a reviewed, mutually compatible platform, device/vendor,
ACK/GKI kernel/module and firmware generation. Public driver packages alone do not
establish the full vendor or recovery chain. Input licensing and redistribution
rights must be assessed separately from availability.

## Gates before deployment

- Establish the exact supported device and maintained release generation.
- Verify source provenance, firmware/security-patch compatibility and signed outputs.
- Define owner-controlled signing, installation, rollback and recovery procedures.
- Qualify phone-critical functions, hardware security, power/thermal behavior and
  update/recovery paths on the actual target.

See the [accepted foundation](../docs/architecture.md) and
[GrapheneOS base assessment](../docs/grapheneos-base-assessment.md). Device-specific
operator access and live inventory are maintained privately.
