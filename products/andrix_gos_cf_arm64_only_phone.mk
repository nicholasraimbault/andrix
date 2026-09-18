# SPDX-License-Identifier: Apache-2.0
# Initial GrapheneOS migration product, not a release or a Pixel device port.
# Require the pinned M1 source check before using this product. Keep legacy
# Cuttlefish network/RKP/provider overrides out until their semantic rebase.
$(call inherit-product, device/google/cuttlefish/vsoc_arm64_only/phone/aosp_cf.mk)
$(call inherit-product, vendor/andrix/andrix.mk)

# GrapheneOS's generic base omits the sample APN database used by Cuttlefish's
# virtual SIM. Restore that existing AOSP input for this emulator product only;
# Pixel/vendor carrier configuration remains a separate device integration.
PRODUCT_COPY_FILES += \
    device/sample/etc/apns-full-conf.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/apns-conf.xml

# First bounded owner-session prototype. Explicit opt-in keeps the established
# baseline reproducible while this new Andrix-owned boundary is qualified.
ifeq ($(ANDRIX_OWNER_SESSION),true)
PRODUCT_PACKAGES += andrixd andrix-session-runner AndrixTerminal
endif

# Android-owned lifecycle observation/cleanup integration is separately gated.
# This does not enable Console-independent Keep; that remains a later native gate.
ifeq ($(ANDRIX_OWNER_LIFECYCLE),true)
ifneq ($(ANDRIX_OWNER_SESSION),true)
$(error ANDRIX_OWNER_LIFECYCLE requires ANDRIX_OWNER_SESSION=true)
endif
$(call soong_config_set_bool,andrix,owner_lifecycle,true)
PRODUCT_PACKAGES += andrix-owner-lifecycle AndrixOwnerLifecycleOverlay
PRODUCT_SYSTEM_SERVER_JARS_EXTRA += system_ext:andrix-owner-lifecycle
# Preserve system-server optimization and let the existing build logic trace
# downstream references from this jar; do not use a broken-order bypass.
SYSTEM_OPTIMIZE_JAVA := true
endif

# Keep candidate is a separate explicit opt-in, never the ordinary session default.
ifeq ($(ANDRIX_OWNER_KEEP),true)
ifneq ($(ANDRIX_OWNER_LIFECYCLE),true)
$(error ANDRIX_OWNER_KEEP requires ANDRIX_OWNER_LIFECYCLE=true)
endif
ifneq ($(ANDRIX_OWNER_COMPILER),true)
$(error ANDRIX_OWNER_KEEP requires the pinned ANDRIX_OWNER_COMPILER=true tmux payload)
endif
$(call soong_config_set_bool,andrix,owner_keep,true)
endif

# Two owner-approved fixed lab fault controls. Normal images select different
# source files without the commands/storage-lock call; a runtime flag is not enough.
$(call soong_config_set_bool,andrix,owner_fault_tests,false)
ifeq ($(ANDRIX_OWNER_FAULT_TESTS),true)
ifneq ($(TARGET_PRODUCT),andrix_gos_cf_arm64_only_phone)
$(error ANDRIX_OWNER_FAULT_TESTS is limited to the GrapheneOS Cuttlefish lab product)
endif
ifneq ($(ANDRIX_OWNER_KEEP),true)
$(error ANDRIX_OWNER_FAULT_TESTS requires ANDRIX_OWNER_KEEP=true)
endif
ifneq ($(TARGET_BUILD_VARIANT),userdebug)
ifneq ($(TARGET_BUILD_VARIANT),eng)
$(error ANDRIX_OWNER_FAULT_TESTS requires userdebug or eng; never a user build)
endif
endif
$(call soong_config_set_bool,andrix,owner_fault_tests,true)
endif

# Fixed native scope factory experiment, not a new product work API. Separate
# from lifecycle fault delegation; never install its control/policy in normal images.
ifeq ($(ANDRIX_OWNER_SCOPE_PROOF),true)
ifneq ($(TARGET_PRODUCT),andrix_gos_cf_arm64_only_phone)
$(error ANDRIX_OWNER_SCOPE_PROOF is limited to the GrapheneOS Cuttlefish lab product)
endif
ifneq ($(ANDRIX_OWNER_SESSION),true)
$(error ANDRIX_OWNER_SCOPE_PROOF requires ANDRIX_OWNER_SESSION=true)
endif
ifneq ($(ANDRIX_OWNER_LIFECYCLE),true)
$(error ANDRIX_OWNER_SCOPE_PROOF requires ANDRIX_OWNER_LIFECYCLE=true)
endif
ifeq ($(ANDRIX_OWNER_KEEP),true)
$(error ANDRIX_OWNER_SCOPE_PROOF cannot be combined with Keep)
endif
ifeq ($(ANDRIX_OWNER_FAULT_TESTS),true)
$(error ANDRIX_OWNER_SCOPE_PROOF cannot be combined with lifecycle fault controls)
endif
ifneq ($(TARGET_BUILD_VARIANT),userdebug)
ifneq ($(TARGET_BUILD_VARIANT),eng)
$(error ANDRIX_OWNER_SCOPE_PROOF requires userdebug or eng)
endif
endif
PRODUCT_PACKAGES += andrix-scope-guardian-probe andrix-scope-worker-probe andrix-scope-proof-client
endif

# Comparative native factory experiments. No default/product work policy changes.
$(call soong_config_set_bool,andrix,factory_init,false)
ifneq ($(ANDRIX_WORK_FACTORY_PROOF),)
ifneq ($(ANDRIX_WORK_FACTORY_PROOF),delegated)
ifneq ($(ANDRIX_WORK_FACTORY_PROOF),init)
$(error ANDRIX_WORK_FACTORY_PROOF must be delegated or init)
endif
endif
ifneq ($(TARGET_PRODUCT),andrix_gos_cf_arm64_only_phone)
$(error ANDRIX_WORK_FACTORY_PROOF is limited to the GrapheneOS Cuttlefish lab product)
endif
ifneq ($(ANDRIX_OWNER_SESSION),true)
$(error ANDRIX_WORK_FACTORY_PROOF requires ANDRIX_OWNER_SESSION=true)
endif
ifneq ($(ANDRIX_OWNER_LIFECYCLE),true)
$(error ANDRIX_WORK_FACTORY_PROOF requires ANDRIX_OWNER_LIFECYCLE=true)
endif
ifeq ($(ANDRIX_OWNER_KEEP),true)
$(error ANDRIX_WORK_FACTORY_PROOF cannot be combined with Keep)
endif
ifeq ($(ANDRIX_OWNER_FAULT_TESTS),true)
$(error ANDRIX_WORK_FACTORY_PROOF cannot be combined with lifecycle fault controls)
endif
ifeq ($(ANDRIX_OWNER_SCOPE_PROOF),true)
$(error ANDRIX_WORK_FACTORY_PROOF cannot be combined with the old fixed-slot proof)
endif
ifneq ($(TARGET_BUILD_VARIANT),userdebug)
ifneq ($(TARGET_BUILD_VARIANT),eng)
$(error ANDRIX_WORK_FACTORY_PROOF requires userdebug or eng)
endif
endif
ifeq ($(ANDRIX_WORK_FACTORY_PROOF),init)
$(call soong_config_set_bool,andrix,factory_init,true)
endif
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.andrix.factory_backend=$(ANDRIX_WORK_FACTORY_PROOF)
PRODUCT_PACKAGES += andrix-factory-manager-probe andrix-factory-guardian-probe andrix-factory-worker-probe andrix-factory-proof-client
endif

# Optional generic service supervision integration. No Andrix job policy in init.
$(call soong_config_set_bool,andrix,delegated_service,false)
ifeq ($(ANDRIX_DELEGATED_SERVICE_PROOF),true)
ifneq ($(TARGET_PRODUCT),andrix_gos_cf_arm64_only_phone)
$(error ANDRIX_DELEGATED_SERVICE_PROOF is limited to the GrapheneOS Cuttlefish lab product)
endif
ifneq ($(TARGET_BUILD_VARIANT),userdebug)
ifneq ($(TARGET_BUILD_VARIANT),eng)
$(error ANDRIX_DELEGATED_SERVICE_PROOF requires userdebug or eng)
endif
endif
ifneq ($(ANDRIX_OWNER_SESSION),true)
$(error ANDRIX_DELEGATED_SERVICE_PROOF requires ANDRIX_OWNER_SESSION=true)
endif
ifneq ($(ANDRIX_OWNER_LIFECYCLE),true)
$(error ANDRIX_DELEGATED_SERVICE_PROOF requires ANDRIX_OWNER_LIFECYCLE=true)
endif
ifneq ($(filter true,$(ANDRIX_OWNER_KEEP) $(ANDRIX_OWNER_FAULT_TESTS) $(ANDRIX_OWNER_SCOPE_PROOF)),)
$(error ANDRIX_DELEGATED_SERVICE_PROOF cannot use Keep or older fault/scope controls)
endif
ifneq ($(ANDRIX_WORK_FACTORY_PROOF),)
$(error ANDRIX_DELEGATED_SERVICE_PROOF cannot use the older factory experiment)
endif
$(call soong_config_set_bool,andrix,delegated_service,true)
PRODUCT_PACKAGES += andrix-delegated-service-probe andrix-delegated-service-client
endif

# Compiler payload is a separate opt-in within the owner environment. Unflagged
# builds retain the original small APEX and do not require the staged compiler.
ifeq ($(ANDRIX_OWNER_COMPILER),true)
ifneq ($(ANDRIX_OWNER_SESSION),true)
$(error ANDRIX_OWNER_COMPILER requires ANDRIX_OWNER_SESSION=true)
endif
$(call soong_config_set_bool,andrix,owner_compiler,true)
endif

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
