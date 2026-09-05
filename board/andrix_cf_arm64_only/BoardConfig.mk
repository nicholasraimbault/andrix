# Reuse Cuttlefish's 64-bit-only board, then add Andrix system_ext policy.
include device/google/cuttlefish/vsoc_arm64_only/BoardConfig.mk

SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/sepolicy/private
