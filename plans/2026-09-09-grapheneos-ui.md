# Existing Android UI follow-up

**Bounded result on 2026-09-09:** ordinary Android setup screens render and normal
Next/Back navigation works. The emulator-only Bluetooth-powered-on expectation was
corrected without enabling the radio or removing Bluetooth services. The real
Cuttlefish boot monitor completed and the guest remained alive for a further
20 minutes of UI observation. Full setup and post-setup launcher behavior remain
unqualified; no credential or screenshot-protection bypass was attempted.

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

## Emulator profile mismatch and correction

The pinned `BluetoothChecker.java` explicitly expects `BluetoothAdapter.isEnabled()`;
this is a **powered-on expectation**, not a generic check that Android can boot
with a radio intentionally off. The pinned GrapheneOS SettingsProvider defaults
Bluetooth off, and the guest repeatedly reported a disabled adapter with its name.
`GceService` makes its boot-completed event depend on that powered-on future.

Cuttlefish provides a read-only, per-product bootconfig switch,
`androidboot.cuttlefish_service_bluetooth_checker=false`, wired through its vendor
init and typed sysprop. The Andrix board change uses that existing switch
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
other bootconfig entries. The full host suite passes **257 tests**. Those are not
an image/runtime pass. The separate incremental `droid hosttar` build completed
with exit 0 in 748.990 seconds, ending `2026-09-09T16:32:05Z`, with image producer
`108d8574dcfc9a09bb29977e67d694e82c94d758`. All 27 images and both host packages were
frozen and rehashed; the signed `/usr` APEX remains byte-identical to the earlier
verified artifact. Other users' busy heavy-work leases were respected, not cleared
or interrupted.

A first observation of this new image stopped at a shell read of the
vendor-internal checker property. The public `ro.boot` input was already `false`;
SELinux correctly prevented shell from reading the private vendor copy. That FAIL
is retained. The corrected observer reads the public boot input and requires the
actual authorized consumer's `Bluetooth checker disabled (by property)` log plus
`VIRTUAL_DEVICE_BOOT_COMPLETED`. No SELinux permission was added.

## Final observed window

A fresh guest on the same `108d857` image passed the shared `/usr` core checks.
The configured boot input was `false`, `bluetooth_on` remained 0, and the Bluetooth
manager reported OFF, never enabled, with zero crashes. Cuttlefish emitted its
real boot-completed event, not a forged host result. This does not test Bluetooth
radio functionality.

The visual/input observations were:

- Genuine GrapheneOS welcome screen, including the expected emulator unlocked-
  bootloader warning. The owner's physical Pixel was not involved.
- Normal Next navigation to Wi-Fi setup, then the visible **Set up without Wi-Fi**
  path. Wi-Fi was not enabled and no connection was provided.
- Date/time and location pages rendered; existing defaults were retained. Network
  location remained off. Normal Back navigation returned to the prior page.
- The credential activity was focused and ready with **SECURE** in its window
  flags. Its protected content was black in screenshots, distinct from the earlier
  not-yet-drawn fallback-home frame. We did not disable that protection or enter a
  credential. Full setup was not completed.
- Settings/Home requests while setup was unfinished remained within onboarding;
  this is not a post-setup launcher qualification.

All 32 recorded UI actions completed through ordinary ADB shell input/observation,
not UIAutomation or permission adoption. The final controller, runner, stop and
capture exited 0. Capture: **62,826 packets, zero kernel-reported drops**, in the
isolated offline namespace (including host-management traffic). This is not
connected privacy or native/Pixel qualification, and the earlier Cuttlefish kernel
hardening limitations still apply.

The original UI window seals 281 files; the vendor-property observer failure seals 52;
the final window seals 1,023. Complete private evidence
`grapheneos-ui-review-20260909T152937Z` seals **4,624 regular files**, excluding symlinks.
Earlier image/runtime seals remain unchanged. Post-build base-source observation
again recorded 1,107 matching clean projects plus a `build/release` Git-diff timeout;
the same-contract single-project retry passed in 5.988 seconds. The original FAIL
is retained, with no source revision or policy change accepted in its place.

## Connected-service review remains separate

The [RKP source review](../docs/grapheneos-connected-policy-review.md) found a real
policy decision before a connected test: GrapheneOS's private attestation proxy
uses Google's provisioning service, and the client constructs device-derived
protocol payloads. A proxy is not automatically compliance with Andrix's literal
zero-Google-service/data requirement. No exception, fake response, blanket consumer
disable or architecture change is adopted by this UI work.
