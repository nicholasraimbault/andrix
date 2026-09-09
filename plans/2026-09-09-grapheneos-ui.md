# Existing Android UI follow-up

## Scope

Continue the owner's requested migration work autonomously: investigate the blank
frame from the [first offline boot](2026-09-08-grapheneos-first-boot.md), using the
same frozen image in a fresh disconnected Cuttlefish guest. This is not a new
Wayland/desktop implementation, phone operation or connected-service approval.
Only normal ADB shell observation/input is used; no permission grants, adopted
identity, fake services or security-setting changes.

## Observed on the original `be031f9` image

The earlier final screenshot was taken shortly after launching SetupWizard.
Its sealed logs recorded an earlier WelcomeActivity first draw taking about
81 seconds under TCG; `sys.boot_completed` alone was not visual readiness.

A new fresh offline test reproduced the black early frame while the display was
**Awake**, fallback home was active and no window had focus. After waiting, the
same unchanged image rendered the genuine GrapheneOS welcome screen. The focused
activity and screenshot agree. Normal Next input subsequently launched Android's
InternetSetupActivity. No renderer or security patch was needed to get the welcome
screen, and the bootloader warning refers to the emulator—not the owner's Pixel.

Longer navigation did **not** finish successfully. Cuttlefish's guest service
reported ten failed readiness checks for Bluetooth and `VIRTUAL_DEVICE_BOOT_FAILED`.
The host then shut QEMU down through QMP, with runner exit 11. The resulting ADB
transport failure is not a successful UI step. The original window/logs/frame and
failure are retained. Thus the short first-boot/core proof still stands, but it
must not be extrapolated to a stable longer UI session.

## Emulator profile mismatch and prepared correction

The pinned `BluetoothChecker.java` explicitly expects `BluetoothAdapter.isEnabled()`;
this is a **powered-on expectation**, not a generic check that Android can boot
with a radio intentionally off. The pinned GrapheneOS SettingsProvider defaults
Bluetooth off, and the guest repeatedly reported a disabled adapter with its name.
`GceService` makes its boot-completed event depend on that powered-on future.

Cuttlefish provides a read-only, per-product bootconfig switch,
`androidboot.cuttlefish_service_bluetooth_checker=false`, wired through its vendor
init and typed sysprop. The prepared Andrix board change uses that existing switch
**only** when `TARGET_PRODUCT=andrix_gos_cf_arm64_only_phone`. The old direct-AOSP
product is unchanged. Bluetooth services, feature declarations, radio state and
GrapheneOS's off-by-default policy are not changed.

This explicitly removes the invalid powered-on requirement from the emulator
profile; it is **not Bluetooth functional qualification**. Do not forge a Bluetooth
success event or disable the entire boot monitor. The follow-up must observe the
configured switch, Bluetooth manager/adapter state, real Cuttlefish boot completion,
and a longer UI session beyond the former failure interval. Other boot/runtime
checks remain active. The old failed image/window remains distinct from the new
producer.

GNU make host tests confirm the setting is confined to this product and preserves
other bootconfig entries. They are not an image or runtime pass. Build/verification
must wait for the exclusive host lease if another user holds it; that work is not
interrupted or bypassed.

## Connected-service review remains separate

The [RKP source review](../docs/grapheneos-connected-policy-review.md) found a real
policy decision before a connected test: GrapheneOS's private attestation proxy
uses Google's provisioning service, and the client constructs device-derived
protocol payloads. A proxy is not automatically compliance with Andrix's literal
zero-Google-service/data requirement. No exception, fake response, blanket consumer
disable or architecture change is adopted by this UI work.
