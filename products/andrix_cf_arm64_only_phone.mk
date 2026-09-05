# Phase 1 product. Keep the first proof independent of a physical device tree.
$(call inherit-product, device/google/cuttlefish/vsoc_arm64_only/phone/aosp_cf.mk)
$(call inherit-product, vendor/andrix/andrix.mk)

# Local Cuttlefish proof configuration, not a future device provisioning policy.
PRODUCT_PACKAGES += \
    andrix-cuttlefish-network.rc \
    AndrixCuttlefishNetworkStackOverlay \
    AndrixCuttlefishConnectivityOverlay

PRODUCT_NAME := andrix_cf_arm64_only_phone
PRODUCT_DEVICE := andrix_cf_arm64_only
PRODUCT_BRAND := Andrix
PRODUCT_MODEL := Andrix Cuttlefish arm64-only phone
PRODUCT_MANUFACTURER := Andrix
