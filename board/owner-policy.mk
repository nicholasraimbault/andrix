SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/sepolicy/private \
    vendor/andrix/owner/sepolicy vendor/andrix/owner/platform/sepolicy
BOARD_SEPOLICY_M4DEFS += andrix_owner_session=true
TARGET_FS_CONFIG_GEN += vendor/andrix/owner/config.fs
