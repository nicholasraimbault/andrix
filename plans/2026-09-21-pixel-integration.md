# Pixel integration after the Cuttlefish platform work

Status: later product work under the [accepted vision](../docs/vision.md). No physical
phone deployment or flashing operation is authorized or qualified by this plan.

## Direction

Cuttlefish/QEMU is the first development and verification environment. Bring the more
mature Andrix system to a selected Pixel using maintained GrapheneOS device/vendor inputs
and tooling where useful. Study the actual device integration and security changes, not
only a list of CVE identifiers. Andrix remains responsible for its source choices, updates,
licensing, signing, recovery and device support.

GrapheneOS is an initial engineering foundation, not Andrix's product policy authority.
Its Pixel qualification is not automatically inherited by an Andrix derivative. AOSP
receives security fixes too, and selective downstream imports can have dependencies that
need review. Avoid an unmaintained mixture of source, firmware, modules and vendor policy.

## Required work

- Select a supported device and a mutually compatible Android/device/vendor/kernel/firmware
  generation. Keep exact provenance and redistribution rights distinct from availability.
- Qualify owner account, Unix, APK, workshop, signing and update behavior against the actual
  hardware. An emulator kernel or device configuration is not a replacement for that work.
- Test radio/telephony, emergency use through an appropriate safe test plan, audio, camera,
  sensors, graphics/input, suspend, battery, thermal and resource pressure behavior.
- Establish installation and restoration plans before any authorized flash. Record backup,
  credential data, key continuity, rollback constraints and the expected verification state.
- Describe workshop physical integrity limitations. Qualify a later locked owner keyed mode
  separately, including hardware root support, truthful boot state and recovery.

The earlier [caiman readiness assessment](2026-09-08-caiman-readiness.md) remains a reference,
not proof of a buildable deployment product. Exact hardware choice and deployment authority
are decisions for this workstream when it begins, not consequences of a successful Cuttlefish
SystemUI experiment.
