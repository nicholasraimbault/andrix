# SPDX-License-Identifier: Apache-2.0
# Initial GrapheneOS migration product, not a release or a Pixel device port.
# Require the pinned M1 source check before using this product. Keep legacy
# Cuttlefish network/RKP/provider overrides out until their semantic rebase.
$(call inherit-product, device/google/cuttlefish/vsoc_arm64_only/phone/aosp_cf.mk)
$(call inherit-product, vendor/andrix/andrix.mk)

# The upstream media_system product includes its Updater for OFFICIAL_BUILD.
# This development product has no Andrix release channel; it must not claim
# official upstream release status or use that channel with different keys.
ifeq ($(TARGET_PRODUCT),andrix_gos_cf_arm64_only_phone)
ifeq ($(OFFICIAL_BUILD),true)
$(error Andrix migration development product requires OFFICIAL_BUILD unset or false)
endif
endif

PRODUCT_NAME := andrix_gos_cf_arm64_only_phone
# Reuse the existing virtual-board wrapper and narrow Andrix system_ext policy.
PRODUCT_DEVICE := andrix_cf_arm64_only
PRODUCT_BRAND := Andrix
PRODUCT_MODEL := Andrix GrapheneOS-base Cuttlefish arm64-only proof
PRODUCT_MANUFACTURER := Andrix
