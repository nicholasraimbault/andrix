# Product-neutral Andrix overlay. Virt and later device products inherit this.

PRODUCT_PACKAGES += \
    dev.andrix.usr \
    andrix.rc

# Root is read-only by the time apexd is ready. This built-in marker makes
# /usr exist in the image before init bind-mounts the APEX over it.
PRODUCT_COPY_FILES += \
    vendor/andrix/init/usr.mountpoint:$(TARGET_COPY_OUT_ROOT)/usr/.andrix-mountpoint

# generic_system owns root's artifact paths. Permit only this Andrix mountpoint
# marker, without disabling or broadly relaxing AOSP's path enforcement.
PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    $(TARGET_COPY_OUT_ROOT)/usr/.andrix-mountpoint
