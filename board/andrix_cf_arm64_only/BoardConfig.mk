# Reuse Cuttlefish's 64-bit-only board, then add Andrix system_ext policy.
include device/google/cuttlefish/vsoc_arm64_only/BoardConfig.mk

SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/sepolicy/private

# The generic Cuttlefish boot reporter demands Bluetooth be powered on.
# GrapheneOS deliberately defaults it off. Scope that powered-on expectation
# out of this emulator product; keep Bluetooth itself and all other boot checks.
# This is not Bluetooth functional qualification or a Pixel configuration.
ifeq ($(TARGET_PRODUCT),andrix_gos_cf_arm64_only_phone)
BOARD_BOOTCONFIG += androidboot.cuttlefish_service_bluetooth_checker=false
ifeq ($(ANDRIX_OWNER_SESSION),true)
BOARD_SEPOLICY_M4DEFS += andrix_owner_session=true
TARGET_FS_CONFIG_GEN += vendor/andrix/owner/config.fs
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/owner/sepolicy
endif
endif
