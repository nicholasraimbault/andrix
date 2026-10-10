# Pixel 9 Pro (caiman): stage 1 design for the nine design items

Status: desk design, 2026-10-09. It answers "Design items" in the
[workshop phone plan](2026-10-09-caiman-workshop-phone.md#design-items) and is the design note that
the plan's stage 1 asks for. An independent review checked it against the source tree, and its
corrections are included. The owner questions at the end are open. Nothing here touched a phone,
downloaded Google's images or built anything.

## How to read this document

- **The source tree** is a GrapheneOS source tree synced at release tag 2026100600, the tag a first
  caiman build would use. Every GrapheneOS file is cited by its path from the tree root at that tag,
  usually with line numbers, for example `build/soong/scripts/gen_build_prop.py:387`. A bare `:NNN`
  continues the source file cited just before it. The pinned 2026081300 tree is named where it
  matters.
- **The caiman record.** adevtool at the tag (revision 17df3b79, 2026-10-06) keeps a text record of
  what it generates for each device. For caiman that is
  `vendor/adevtool/vendor-skels/google_devices/caiman`. Its README says the record is kept to track
  changes and is not used for generation (`vendor/adevtool/vendor-skels/README.md:1-6`). This
  document calls that directory "the caiman record" and cites it by its path. The real module only
  exists after stage 6.
- **Andrix files** are cited by repository path, for example
  `products/andrix_gos_cf_arm64_only_phone.mk:49`. The workshop plan is cited by section name.
- **Public pages** were fetched on 2026-10-09:
  - the [GrapheneOS FAQ](https://grapheneos.org/faq), anchors `default-connections`,
    `other-connections` and `trademark`, SHA-256
    `a5cf1229f0d09e52d310e573ebfbd39eea980520d0213e21505291daaddda538`;
  - the [GrapheneOS usage guide](https://grapheneos.org/usage), anchor `esim-support`, SHA-256
    `215f8a50c227aceb9aa9f2ee808b0c9ac2043e3d7bc7302e21e1a9566acecfda`;
  - the [GrapheneOS build guide](https://grapheneos.org/build), sections on release keys, APEX
    components and `OFFICIAL_BUILD`, SHA-256
    `34b5f9eead6decdf8d866b79a70e9eccae008e508c562915bfbdd6cb94dcc88f`.
- **Kernel configuration.** The caiman kernel prebuilt embeds its configuration. It was read by
  decompressing `device/google/caimito-kernels/6.1/grapheneos/Image.lz4` (SHA-256
  `3653ad0383c23fa2835b42806c89b9b544ea2dbfc47bdb35c2759db538cb4435`) and unpacking the gzip data
  between the `IKCFG_ST` and `IKCFG_ED` markers. The configuration reports Linux 6.1.177. Its line
  numbers are cited as `kconfig:NNN`.
- **Inference** marks a conclusion drawn from sources and not observed. Other statements of fact
  rest on the lines they cite. The design sections propose. They report no observation of a build
  or a phone.
- **Checks.** The independent review checked over 100 citations of this document's first version
  against the tree and found one wrong line number, corrected here. Every citation added or changed
  after the review was checked again against the tree at the tag on 2026-10-09.

## Summary

| Item | Design in brief | Needed before stage 6 |
|---|---|---|
| 1 Product and board | New product `andrix_caiman` inheriting the generated `caiman.mk`. Board level policy variables set from the product phase through a fragment. `BUILD_ID` derived from the generated envsetup script. Lab guards move into `andrix.mk`. | The files, host make tests, decision 3 for the lunch choice, separate output directories. |
| 2 Neverallow check | Host tool on the flashed install zip: hash match, owner types present, 28 Andrix rules with `-w` and no warning allowed, one mutant per rule, a recompiled control tied to the loaded policy, AOSP rules compared with GrapheneOS's release policy, and a `secilc` run without `-N` for extended permission rules. | Tool and witness table reviewed, `sepolicy-analyze`, `secilc` and `checkpolicy` built and pinned, decision 3 for the rule source. |
| 3 Services overlay | Keep the one entry overlay. A check reads every APK manifest, proves no other overlay of `android` defines the array, and computes the union if one ever does. | The check with fixtures. |
| 4 Owner resource controls | No vendor change. Inference from sources: memory is on cgroup v2 down to the owner's directory. Build check on the stage 6 images, including the vendor task profiles and init scripts, plus targeted phone readings. | The check with fixtures. |
| 5 Product identity | Keep brand, manufacturer, model, device and all attestation values. Make the product name and build number Andrix's own. The checkers learn the Andrix build number. | Owner review of the identity. |
| 6 Signing and updates | Reviewed patch to GrapheneOS's release script plus a wrapper that derives the base tag and the build number from the verified tree before the build. Console and APEX on the workshop release key. Guard against `OFFICIAL_BUILD` for every product. Update admission with an OTA reader. | Decisions 2 and 3, and the source verifier pinned to 2026100600. The workshop key digest is recorded at stage 6, before the gate. |
| 7 Hardware method | Method confirmed. Eight gaps named, with a failing control for the adb order. | Readings defined for the gaps. |
| 8 Connected policy | Endpoint inventory from source. Keep GrapheneOS defaults and the vendor provisioning hostname. Refuse the emulator profile in phone images. | The configuration check, an owner choice on observing traffic. |
| 9 Boot state | Reviewed patch removes the property from `gen_build_prop.py`. Build check, a phone reading compared with the GrapheneOS baseline, and each daily app opened at stage 8. | The patch, its inspector and the check. |

## 1. Product and board composition

### What the sources show

- The generated module registers its firmware only when `TARGET_DEVICE` is caiman
  (`vendor/adevtool/vendor-skels/google_devices/caiman/Android.mk:6-9`). Its board and product
  files start with the comment `# Generated by adevtool; do not edit`
  (`vendor/adevtool/vendor-skels/google_devices/caiman/BoardConfig.mk:1`,
  `vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:1`).
- The generated product sets `PRODUCT_NAME := caiman` and `PRODUCT_DEVICE := caiman`
  (`vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:20-21`). Product names must be
  unique among all registered products (`build/make/core/product_config.mk:215-218`). An Andrix
  caiman product therefore needs its own name. This document uses `andrix_caiman`.
- The board file is found by searching `device/` and `vendor/` for exactly one
  `*/caiman/BoardConfig.mk`, and two matches stop the build
  (`build/make/core/board_config.mk:229-246`). `TARGET_DEVICE_DIR` is accepted only from the
  command line (`build/make/core/board_config.mk:224-228`). soong_ui turns `NAME=value` arguments
  into environment variables (`build/soong/ui/build/config.go:1266-1270`) and passes its own
  computed value to Kati (`build/soong/ui/build/kati.go:269`). So a caiman build always uses the
  generated board file. Andrix cannot add a second board file for caiman.
- Kati evaluates product makefiles before the board file, in one make process
  (`build/make/core/envsetup.mk:350` and `:366`). Importing a product clears and copies only the
  product variables (`build/make/core/node_fns.mk:183-207`), so other variables a product makefile
  sets are still set when the board file runs. GrapheneOS's caiman configuration uses the same
  order. `vendor/adevtool/config/mk/google_devices/device/caiman/device.mk:3` sets
  `TARGET_KERNEL_DIR` in the product phase.
  `vendor/adevtool/config/mk/google_devices/common/BoardConfig-common.mk:19` and `:36` read it in
  the board phase, and
  `vendor/adevtool/config/mk/google_devices/common/BoardConfig-common-gs201-plus.mk:6-9` stops the
  build when the value is missing. Inference: product makefile variables do reach the board file,
  or GrapheneOS's own caiman builds would stop there.
- The generated board appends its policy directories with `+=`
  (`vendor/adevtool/vendor-skels/google_devices/caiman/BoardConfig.mk:96-100`). It sets no
  `BOARD_SEPOLICY_M4DEFS` and no `TARGET_FS_CONFIG_GEN`. A search of `vendor/adevtool/config`
  finds no file in adevtool's zumapro or caiman chain that sets those variables. Only the laguna
  and malibu platforms append system_ext directories.
- `BUILD_ID` is taken from `BUILD_ID_$(TARGET_PRODUCT)` (`build/make/core/version_util.mk:43`), and
  a product security patch override from `PLATFORM_SECURITY_PATCH_$(TARGET_PRODUCT)` (`:65-67`).
  `lunch` sources `vendor/*/<product>/cmds-for-envsetup.sh` and skips it silently when none exists
  (`build/make/envsetup.sh:454-490`, called at `:498`). For caiman that script exports
  `BUILD_ID_caiman="CP3A.261005.005"`
  (`vendor/adevtool/vendor-skels/google_devices/caiman/cmds-for-envsetup.sh:1-2`). The generated
  product refuses any other `BUILD_ID`
  (`vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:6-8`). For a product named
  `andrix_caiman` no script would be found. `BUILD_ID` would then come from
  `build/make/core/build_id.mk:26` (`CP2A.260605.016`), and product configuration would stop at that
  check.
- The product name changes nothing else in the device makefiles. The only test of `TARGET_PRODUCT`
  in adevtool's makefiles and the caiman record adds a debug package for every product except lynx
  and tangorpro, so `andrix_caiman` gets what `caiman` gets
  (`vendor/adevtool/config/mk/google_devices/common/device-common.mk:63-65`). The other tests in
  `build/make/target/product` are in generic system image products, which a caiman product does not
  inherit.
- `PRODUCT_OUT` is `out/target/product/$(TARGET_DEVICE)` (`build/make/core/envsetup.mk:363`). An
  Andrix caiman build and an unmodified GrapheneOS caiman build write the same directory if they
  share an output tree.
- The Cuttlefish board adds `vendor/andrix/sepolicy/private` for every product
  (`board/andrix_cf_arm64_only/BoardConfig.mk:4`). It adds the owner M4 definition, `config.fs` and
  the owner policy only for the GrapheneOS Cuttlefish product
  (`board/andrix_cf_arm64_only/BoardConfig.mk:10-17`). The lab policy directories sit under the same
  condition (`:18-36`).
- The lab vehicles refuse other products from inside the Cuttlefish product makefile
  (`products/andrix_gos_cf_arm64_only_phone.mk:49-51`, `:66-68`, `:97-99`, `:146-148`). A caiman
  product never evaluates that file. Today these checks would not run for a caiman build at all.
  Lab flags in the environment would be ignored, not refused.
- `ANDRIX_WORK_FACTORY_PROOF` is switched on by any value, and the Cuttlefish product then accepts
  only `delegated` or `init` (`products/andrix_gos_cf_arm64_only_phone.mk:91-95`).
- The Cuttlefish product copies AOSP's sample APN database into the product partition as
  `etc/apns-conf.xml`, for the emulator's virtual SIM only
  (`products/andrix_gos_cf_arm64_only_phone.mk:8-12`).
- `inherit-product` imports the inherited file after the inheriting file's own lines
  (`build/make/core/node_fns.mk:190` then `:199-203`). A value set in `andrix.mk` therefore
  overrides what the inheriting product set before it.
- AID 7500 in `owner/config.fs:3-4` lies in the range reserved for system_ext
  (`system/core/libcutils/include/private/android_filesystem_config.h:208-210`). adevtool writes a
  `config.fs` only when the stock image defines partition groups
  (`vendor/adevtool/src/build/make.ts:270-287`). The caiman record has none.
- `PRODUCT_VALIDATION_CHECKS` runs Starlark checks after the board file
  (`build/make/core/envsetup.mk:373`). They see the sepolicy directory lists among the board
  variables (`build/make/core/product_validation_checks.mk:28-40`). Each check file must be named
  with a path that starts with `//` and ends with `.scl`
  (`build/make/core/product_validation_checks.mk:25-26`).

### Design

Files added:

- `products/andrix_caiman.mk`
  - inherits `vendor/google_devices/caiman/caiman.mk` and `vendor/andrix/andrix.mk`, as the
    Cuttlefish product inherits its base and `andrix.mk`
    (`products/andrix_gos_cf_arm64_only_phone.mk:5-6`);
  - sets `PRODUCT_NAME := andrix_caiman`, `PRODUCT_DEVICE := caiman` and the identity of item 5;
  - fixes the phone's composition in the file: the owner session packages and the owner lifecycle
    packages, soong configuration, system server jar and overlay, exactly as the Cuttlefish product
    enables them when both opt ins are true (its session and lifecycle blocks,
    `products/andrix_gos_cf_arm64_only_phone.mk:14-32`). Keep and the compiler payload stay out, as
    "Settled and chosen" below records;
  - carries no `PRODUCT_COPY_FILES` line for an APN database;
  - refuses any `ANDRIX_*` composition variable whose `$(origin)` is the environment or the command
    line, so the image holds only what the file states;
  - includes `board/owner-policy.mk` in the product phase;
  - adds `//vendor/andrix/board/owner-policy.scl` to `PRODUCT_VALIDATION_CHECKS`.
- `board/owner-policy.mk`, with only normal additions and no product condition:

  ```make
  SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/sepolicy/private \
      vendor/andrix/owner/sepolicy vendor/andrix/owner/platform/sepolicy
  BOARD_SEPOLICY_M4DEFS += andrix_owner_session=true
  TARGET_FS_CONFIG_GEN += vendor/andrix/owner/config.fs
  ```

  It names no `tests/` directory. The Cuttlefish board keeps its own conditional lines, which
  depend on environment opt ins that the caiman product refuses.
- `board/owner-policy.scl`, the validation check. After the board file it requires each owner
  directory exactly once in `SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS` and refuses any directory under
  `vendor/andrix/tests/`.
- `andrix_caiman/cmds-for-envsetup.sh` at the repository root, which `lunch` finds as
  `vendor/andrix/andrix_caiman/cmds-for-envsetup.sh`. It sources
  `vendor/google_devices/caiman/cmds-for-envsetup.sh`, then exports `BUILD_ID_andrix_caiman` from
  `BUILD_ID_caiman` and copies or unsets `PLATFORM_SECURITY_PATCH_andrix_caiman` the same way. It
  carries no build ID of its own, so the value always comes from the generated module, and the
  generated `caiman.mk` still checks it. It uses `return`, never `exit`, because `lunch` sources it
  into the operator's shell.

Files changed:

- `andrix.mk`: lab guards for every Andrix product. For `ANDRIX_OWNER_FAULT_TESTS`,
  `ANDRIX_OWNER_SCOPE_PROOF`, `ANDRIX_WORK_FACTORY_PROOF`, `ANDRIX_DELEGATED_SERVICE_PROOF`,
  `ANDRIX_OWNER_WORK_PROOF`, `ANDRIX_OWNER_WORK_SERVICE_PROOF` and `ANDRIX_OWNER_WORK_CE_PROOF`, the
  build stops unless `TARGET_PRODUCT` is `andrix_gos_cf_arm64_only_phone`. Each guard tests whether
  the variable has any value, not whether it is `true`, because `ANDRIX_WORK_FACTORY_PROOF` takes
  `delegated` or `init`. The guards only stop the build and set nothing, because `andrix.mk` is
  imported after the product's own lines. The existing guards in the Cuttlefish product stay. The
  `OFFICIAL_BUILD` guard of item 6 also moves here.
- `AndroidProducts.mk`: registers `products/andrix_caiman.mk` and the lunch choice
  `andrix_caiman-cur-user`, plus `-cur-userdebug` only if decision 3 chooses it.

Operation: Andrix caiman builds and the unmodified GrapheneOS comparison build of gate step 2 use
separate output directories.

### Qualification and failing controls

Stage 1, host only, with GNU make and stub parent files, as the existing tests already do
(`scripts/proof/tests/test_owner_session.py:15-43`, `scripts/proof/tests/test_lifecycle_faults.py:41-65`):

- For each lab flag, `andrix.mk` with `TARGET_PRODUCT=andrix_caiman` stops with the lab message.
  The test sets each flag to `true`, and `ANDRIX_WORK_FACTORY_PROOF` also to `delegated` and
  `init`. With the Cuttlefish product name and that flag's other requirements it passes. Failing
  control: the same test against today's `andrix.mk` fails, because nothing refuses there.
- `products/andrix_caiman.mk` with a stub `caiman.mk`, followed by a stub generated board that
  appends its own directories, prints final values holding each owner directory, the M4 definition
  and `config.fs` once, and no `tests/` directory. Failing control: a stub board that assigns
  `SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS :=` makes the test fail. In a real build the Starlark check
  covers that case.
- An `ANDRIX_*` composition variable in the environment stops the caiman product. Control: unset
  passes.
- The package list of the caiman product equals the Cuttlefish product's normal list with session
  and lifecycle on, minus Cuttlefish packages. A removed package fails the test. The test also reads
  the product's copied files and refuses the emulator APN copy. Failing control: a stub product that
  carries that copy line fails.
- `cmds-for-envsetup.sh`, sourced with a stub generated script, exports the stub's value. Failing
  controls: a missing generated script, or one without `BUILD_ID_caiman`, returns an error and
  exports nothing.

Stage 6, with the build slot: `get_build_var` for the three board variables, the policy check of
item 2 (owner types present), `system_ext/etc/passwd` and `group` naming `system_ext_andrix` with
7500 (inference: the file system configuration generator writes system_ext range entries there),
and `ro.product.device=caiman` (gate step 6).

### Unverified until a caiman build

- That this product goes through Kati product configuration and not the Starlark path
  (`build/make/core/product_config.mk:229-231`). Inference: that path is off unless a product is
  listed for it.
- That the module generated at stage 6 equals the caiman record.
- That `lunch` sources the Andrix envsetup script. `build/make/envsetup.sh:463-469` accepts exactly
  one match, and `vendor/*/andrix_caiman/` has one.

## 2. The neverallow check

### What the sources show

- adevtool adds `SELINUX_IGNORE_NEVERALLOWS := true` whenever it extracted vendor policy
  (`vendor/adevtool/src/build/make.ts:538-547`). The caiman record has it at
  `vendor/adevtool/vendor-skels/google_devices/caiman/BoardConfig.mk:101`, and the pinned record at
  line 82. adevtool drops `neverallow` while parsing the stock policy
  (`vendor/adevtool/src/processor/sepolicy.ts:436-438`). It keeps `neverallowx`. Five remain in
  `vendor/adevtool/vendor-skels/google_devices/caiman/sepolicy/vendor/sepolicy_ext.cil:2426-2427`
  and `:2439-2441`.
- Those five reach the installed vendor policy. `system/sepolicy/Android.bp:456` appends the
  `sepolicy_ext.cil` files of the vendor policy directories (`system/sepolicy/Android.bp:93-96`) to
  `vendor_sepolicy.unversioned.cil` (`:452-460`), through
  `system/sepolicy/build/soong/policy.go:426-430`. The installed `vendor_sepolicy.cil` is the
  versioned module built from it (`:462-475`). Its `version_policy` tool writes every rule back out
  (`system/sepolicy/tools/version_policy.c:187`), `neverallowx` included
  (`external/selinux/libsepol/cil/src/cil_write_ast.c:1172-1181`).
- With the flag, `secilc` gets `-N` both when it checks each CIL file and when it builds the binary
  (`system/sepolicy/build/soong/policy.go:444-446`, `:568-570`). The neverallow test module only
  writes its timestamp (`system/sepolicy/build/soong/sepolicy_neverallow.go:114-118`). Its two
  configuration modules exist anyway, because the load hook creates them in every case
  (`system/sepolicy/build/soong/sepolicy_neverallow.go:77-104`). One of them,
  `sepolicy_neverallows.sepolicy_analyze.conf`, holds every policy source
  (`system/sepolicy/Android.bp:943-953`) expanded by m4 for the `user` variant, without build test
  rules, with line markers (`system/sepolicy/build/soong/policy.go:275-298`, `-s` at `:296`).
- Init loads `/vendor/etc/selinux/precompiled_sepolicy` only when three hash file pairs match
  (`system/core/init/selinux.cpp:133-184`), and never when it uses the userdebug platform policy
  (`:239-259`). It prefers `/odm/etc/selinux/precompiled_sepolicy` whenever that file exists
  (`system/core/init/selinux.cpp:141-144`). caiman has no odm partition
  (`vendor/adevtool/vendor-skels/google_devices/caiman/BoardConfig.mk:10`, `:68-92`). Without a
  precompiled policy init compiles the CIL files on the phone with `-N`
  (`system/core/init/selinux.cpp:350-392`). Each hash is the SHA-256 of a policy CIL file followed
  by its mapping file (`system/sepolicy/Android.bp:535-584`). The precompiled policy is built from
  those CIL files and the vendor ones (`system/sepolicy/Android.bp:680-732`). The build and init
  list the CIL files in different orders (`system/sepolicy/Android.bp:700-710`,
  `system/core/init/selinux.cpp:350-391`). Release signing refuses a `userdebug_plat_sepolicy.cil`
  in system_ext unless told otherwise
  (`build/make/tools/releasetools/sign_target_files_apks.py:133-136`).
- `sepolicy-analyze neverallow` reads rules in their expanded form
  (`system/sepolicy/tools/sepolicy-analyze/README`, section "NEVERALLOW CHECKING"). With `-w` it
  prints a warning to standard error for each undefined type, attribute, class or permission and
  drops the name (`system/sepolicy/tools/sepolicy-analyze/neverallow.c:115-118`, `:249-251`,
  `:340-342`). Without `-w` the name is dropped silently. Warnings do not change the exit status.
  It handles `self` and `*` (`:100-104`, `:326-331`). It matches only the exact keyword `neverallow`
  (`:379`, `:404`), so it never checks `neverallowxperm` rules. With no rule at all it fails
  (`:438`). It reports each violation through the library's error output as `neverallow violated
  by allow S T:C {perms };` (`external/selinux/libsepol/src/assertion.c:47-68`).
- GrapheneOS's own test, when it runs, accepts warnings. It checks only the exit status
  (`system/sepolicy/build/soong/sepolicy_neverallow.go:168-176`).
- `secilc` without `-N` reports every violated `neverallow` and `neverallowx`, not only the first,
  and fails after the whole pass (`external/selinux/libsepol/cil/src/cil_binary.c:4951-4958`,
  `:4973-4980`, `:5292-5316`).
- Andrix has 28 literal rules. There are 17 in `owner/sepolicy/andrix_owner.te` (lines 42, 57, 58,
  78, 84 to 89 and 92 to 98), 5 in `owner/sepolicy/andrix_terminal.te:20-24`, 2 in
  `owner/platform/sepolicy/owner_lifecycle.te:7` and `:13`, and 4 in the bridge patch
  (`patches/grapheneos-2026081300/owner-session-policy.patch:14-17`). The patch also narrows two
  AOSP rules, which start at `system/sepolicy/private/domain.te:1959` and `:2040` in the 2026100600
  tree (patch hunks at `patches/grapheneos-2026081300/owner-session-policy.patch:30-33`). The carry
  report classes that target file as identical at both tags. `sepolicy/private` holds no rule today.
- Andrix's files also call AOSP macros that emit rules for Andrix types. `create_pty` emits a
  `neverallowxperm` rule for `andrixd_devpts` and `andrix_owner_devpts`
  (`system/sepolicy/public/te_macros`, definition of `create_pty`). `system_internal_prop`,
  `app_domain` and `add_service` emit plain rules.
- `secilc`, `simg2img`, `lpunpack`, `debugfs_static` and `aapt2` are in the otatools package
  (`build/make/core/Makefile:5953-6037`). `sepolicy-analyze` is not. `checkpolicy` is a host tool of
  the tree (`external/selinux/checkpolicy/Android.bp:38-52`). It reads a binary policy with `-b` and
  writes CIL with `-C` (`external/selinux/checkpolicy/checkpolicy.c:416`, `:422`). The policy
  version is 30 (`system/sepolicy/build/soong/policy.go:31`, `system/core/init/Android.bp:496`).

### Design

A host tool, `scripts/pixel/neverallow_check.py`, runs after the build. It writes a JSON report and
exits 0 to pass and 1 to refuse, like the other Pixel checkers (`scripts/pixel/README.md:8-10`).

**Outputs it reads.**

1. The Andrix install zip to be flashed, after `scripts/pixel/install_zip.py` identified it. From
   `vbmeta.img`, the base tag property and the build fingerprints. From the super splits, rebuilt
   with `simg2img` and `lpunpack` as `scripts/pixel/install_zip.py` already does, the partition
   images. Files are read from the ext4 images with `debugfs`:
   - vendor: `/etc/selinux/precompiled_sepolicy` and its three
     `precompiled_sepolicy.{plat,system_ext,product}_sepolicy_and_mapping.sha256` files,
     `vendor_sepolicy.cil`, `plat_pub_versioned.cil`, `plat_sepolicy_vers.txt` and
     `genfs_labels_version.txt`;
   - system: `/system/etc/selinux/plat_sepolicy.cil`, `plat_sepolicy_and_mapping.sha256`,
     `mapping/<version>.cil`, the matching `.compat.cil` when present,
     `plat_sepolicy_genfs_<version>.cil`, and `/system/build.prop`;
   - system_ext and product: `/etc/selinux/<partition>_sepolicy.cil`,
     `<partition>_sepolicy_and_mapping.sha256` and `mapping/<version>.cil`.
2. The official GrapheneOS install zip of the same base tag, the way back kit that
   `scripts/pixel/install_zip.py` verified, read the same way.
3. The expanded rule file of the Andrix build. For a user build this is the output of
   `m sepolicy_neverallows.sepolicy_analyze.conf`. For a userdebug build it is an Andrix
   `se_policy_conf` module with the same sources and the real variant, because the existing module
   is always expanded as `user` (`system/sepolicy/build/soong/sepolicy_neverallow.go:96`). Its
   SHA-256 goes into the release record when the build ends.
4. From the Andrix commit that was built: the policy sources, every Andrix patch to
   `system/sepolicy`, and a witness table, `scripts/pixel/neverallow_witnesses.json`.
5. Host tools pinned by SHA-256, as `scripts/pixel/install_zip.py:47-55` pins its own:
   `sepolicy-analyze`, `secilc` and `checkpolicy` from the build's host output, and `debugfs`,
   `simg2img` and `lpunpack`. The pins follow the base tag. Each tag has one reviewed set of
   digests for `sepolicy-analyze`, `secilc` and `checkpolicy`, added in the pin review that a new
   tag already needs (`scripts/proof/grapheneos_source.md:30`). The tool reads the base tag from the
   image's signed `com.andrix.build.base_tag` property and refuses a tag without a set. The release
   wrapper confirms that the build's own host tools hash to that set. The 2026081300 set serves
   only the stage 1 corpus.

**Steps.**

- **A. The policy the phone loads.** The vendor image carries a precompiled policy, and no image
  carries `/odm/etc/selinux/precompiled_sepolicy`, which init would prefer. The three hash pairs are
  equal and not empty. Each hash is computed again from its CIL file and mapping file and must
  equal both copies. The mapping file is the one the vendor's version file names, which init loads.
  The build hashes the `current` mapping (`system/sepolicy/Android.bp:382-390`), so a vendor
  version that differs refuses, which fails closed. An image that carries `userdebug_plat_sepolicy.cil` is refused. On an unlocked
  phone booted with a debug ramdisk, init uses that file and compiles the policy instead of loading
  this binary (`system/core/init/selinux.cpp:205-222`, `:239-249`). The flash script check of
  rule 6 already keeps debug boot images off the phone.
- **B. The owner policy is present.** `sepolicy-analyze <policy> attribute domain` lists `andrixd`,
  `andrix_owner` and `andrix_terminal`. The first two exist only when `andrix_owner_session=true`
  (`patches/grapheneos-2026081300/owner-session-policy.patch:8-11`), and the third only when the
  owner policy directory is included (`owner/sepolicy/andrix_terminal.te:3`).
- **C. Andrix rules in expanded form.** The sources are every Andrix policy directory the product
  adds, derived from `board/owner-policy.mk`, and every Andrix patch to `system/sepolicy` for the
  base tag, not a fixed list. For a patch, the text at a line is the text after its leading `+`. A
  hunk that removes a `neverallow` line or adds an exclusion inside one refuses unless the witness
  table records it, as it records the two narrowings of the bridge patch. The expanded rule file's
  digest must equal the one in the release record. Each witness table entry holds
  the source file and line, the literal rule, its expected expansion and its witness. The tool
  requires three things. The literal text at that line in the built commit equals the entry. Every
  literal `neverallow` in those sources has exactly one entry. The expected expansion appears in the
  build's expanded rule file. The expansions are short. Only `capability_class_set`
  (`system/sepolicy/public/global_macros:5`), `no_x_file_perms`
  (`system/sepolicy/public/neverallow_macros:6`) and `userdebug_or_eng`
  (`system/sepolicy/public/te_macros:583`) occur.
- **D. Andrix rules on the loaded policy.** `sepolicy-analyze <precompiled_sepolicy> neverallow -w
  -f <the 28 rules>`. It passes only with exit status 0, no violation line and nothing at all on
  standard error. Warnings and violations both go to standard error, so this catches both. With
  `-w` the tool also prints "Empty class set" and "Empty permission set" there
  (`system/sepolicy/tools/sepolicy-analyze/neverallow.c:268`, `:361`), and both fail D.
- **E. Mutants, and a control tied to the loaded policy.** The policy is compiled again from the CIL
  files of step A with init's arguments (`system/core/init/selinux.cpp:350-392`):
  `secilc <plat_sepolicy.cil> -m -M true -G -N -v -c 30 <mapping>` and the other files in init's
  order: the platform compat file, system_ext with its mapping and compat file, product with its
  mapping, `plat_pub_versioned`, vendor, `odm_sepolicy.cil` and genfs, each optional file only when
  present (`system/core/init/selinux.cpp:298-302`, `:327-330`, `:371-388`). First the control. The
  recompiled binary and the loaded `precompiled_sepolicy` are both decompiled with
  `checkpolicy -M -b -C`, because the policy is MLS
  (`external/selinux/checkpolicy/checkpolicy.c:592-597`), and the two outputs must be equal. Only then does the control
  stand for the policy the phone loads. The control must pass all 28 rules. Then, for each rule, one
  more CIL file holding that rule's witness `allow` statement is added. Each mutant must fail its
  own rule checked alone with `-n`, and the whole set. A witness that does not compile, or a mutant
  that passes its own rule, fails the tool.
- **F. AOSP rules as patched.** Set B is every other `neverallow` in the build's expanded rule file:
  AOSP's rules as patched, the device rules, and the rules macros emit for Andrix types. It runs on
  the Andrix policy and on GrapheneOS's official precompiled policy of the base tag. Violation lines
  are normalized to source, target, class and permission. A line found in both is reported as a
  vendor policy finding. A line found only in the Andrix policy fails the gate. For these rules a
  warning fails unless the same rule gives the same warning on the official policy. Warnings on the
  official policy about names that only the Andrix policy defines are expected and do not count.
  On the official policy the exclusions of `andrix_owner` drop silently, which is correct there
  (`system/sepolicy/tools/sepolicy-analyze/neverallow.c:115-118`). A rule that loses a name on both
  policies is listed in the report, so its weaker coverage stays visible. A warning names the
  undefined name, not the rule. Comparing warning lines by count decides as a comparison by rule
  would, because both runs read the same rule file and a name undefined only in the Andrix policy
  always adds lines. The report lists the rules that name each warned name. The official policy is
  read through the verified way back kit, and its hash pairs are checked as in step A.
- **G. Extended permission rules, an addition to the plan's parts.** `secilc` runs without `-N` over
  the same CIL set, with the build's own check flags
  (`system/sepolicy/build/soong/policy.go:432-447`). It checks every `neverallow` and `neverallowx`
  statement the CIL files carry. The vendor file carries the five vendor `neverallowx` rules, as
  shown above. Inference: the platform files carry their statements too, since init passes `-N` to
  skip them (`system/core/init/selinux.cpp:353`). The comparison unit is one violated rule and one
  offending rule. Each generated attribute name in either is replaced by its `typeattributeset`
  expression from the same run's CIL files, resolved recursively, and a name that cannot be resolved
  refuses. File names and line positions are dropped, because the bridge patch shifts lines in
  `system/sepolicy/private/domain.te`. The run's pairs are compared with the same run on the
  official release, and a pair that only the Andrix run shows fails the gate. G cannot see a change
  in the members of a named attribute, such as Andrix domains in `domain`. This covers the `create_pty` rule for
  the Andrix terminal types and the five vendor `neverallowx` rules, which step D cannot see.

**Witness table.** Each witness is one CIL `allow` inside the rule. It was chosen so that it does
not also violate a different Andrix rule, where that is possible.

| # | Rule | Witness |
|---|---|---|
| 1 | `owner/sepolicy/andrix_owner.te:42` devpts of the owner | `(allow andrix_terminal andrix_owner_devpts (chr_file (read)))` |
| 2 | `owner/sepolicy/andrix_owner.te:57` home sockets | `(allow andrixd andrix_home_file (sock_file (create)))` |
| 3 | `owner/sepolicy/andrix_owner.te:58` owner `connectto` | `(allow andrixd andrix_owner (unix_stream_socket (connectto)))` |
| 4 | `owner/sepolicy/andrix_owner.te:78` owner `ptrace` | `(allow andrix_owner init (process (ptrace)))`, not `andrixd`, which rule 8 also covers |
| 5 | `owner/sepolicy/andrix_owner.te:84` owner Binder | `(allow andrix_owner andrixd (binder (call)))` |
| 6 | `owner/sepolicy/andrix_owner.te:85` session service | `(allow andrix_owner andrix_session_service (service_manager (find)))` |
| 7 | `owner/sepolicy/andrix_owner.te:86` cgroup writes | `(allow andrix_owner cgroup_v2 (file (write)))` |
| 8 | `owner/sepolicy/andrix_owner.te:87` signals to `andrixd` | `(allow andrix_owner andrixd (process (sigkill)))` |
| 9 | `owner/sepolicy/andrix_owner.te:88` `andrixd_exec` | `(allow andrix_owner andrixd_exec (file (execute)))` |
| 10 | `owner/sepolicy/andrix_owner.te:89` home code in `andrixd` | `(allow andrixd andrix_home_file (file (entrypoint)))` |
| 11 | `owner/sepolicy/andrix_owner.te:92` entry execute | `(allow shell andrix_owner_entry (file (execute)))` |
| 12 | `owner/sepolicy/andrix_owner.te:93` entry without transition | `(allow andrix_owner andrix_owner_entry (file (execute_no_trans)))` |
| 13 | `owner/sepolicy/andrix_owner.te:94` PID property | `(allow shell andrix_owner_pid_prop (property_service (set)))` |
| 14 | `owner/sepolicy/andrix_owner.te:95` console socket | `(allow untrusted_app andrix_console_socket (unix_stream_socket (read)))` |
| 15 | `owner/sepolicy/andrix_owner.te:96` home directories | `(allow untrusted_app andrix_home_file (dir (add_name)))` |
| 16 | `owner/sepolicy/andrix_owner.te:97` home files | `(allow isolated_app andrix_home_file (lnk_file (read)))` |
| 17 | `owner/sepolicy/andrix_owner.te:98` capabilities | `(allow andrixd self (capability (chown)))` |
| 18 | `owner/sepolicy/andrix_terminal.te:20` | `(allow andrix_terminal andrix_home_file (dir (remove_name)))` |
| 19 | `owner/sepolicy/andrix_terminal.te:21` | `(allow andrix_terminal andrix_home_file (file (open)))` |
| 20 | `owner/sepolicy/andrix_terminal.te:22` | `(allow andrix_terminal andrixd_devpts (chr_file (ioctl)))` |
| 21 | `owner/sepolicy/andrix_terminal.te:23` | `(allow andrix_terminal andrix_owner_entry (file (execute)))`, which also violates rule 11 by design of the rules |
| 22 | `owner/sepolicy/andrix_terminal.te:24` | `(allow andrix_terminal andrix_owner (process (sigstop)))` |
| 23 | `owner/platform/sepolicy/owner_lifecycle.te:7` | `(allow untrusted_app andrix_lifecycle_service (service_manager (find)))` |
| 24 | `owner/platform/sepolicy/owner_lifecycle.te:13` | `(allow shell ctl_andrix_owner_prop (property_service (set)))` |
| 25 | `patches/grapheneos-2026081300/owner-session-policy.patch:14` | `(allow andrix_owner app_data_file (file (execute)))` |
| 26 | `patches/grapheneos-2026081300/owner-session-policy.patch:15` | `(allow shell andrix_home_file (file (execute_no_trans)))` |
| 27 | `patches/grapheneos-2026081300/owner-session-policy.patch:16` | `(allow init andrix_owner (process (transition)))` |
| 28 | `patches/grapheneos-2026081300/owner-session-policy.patch:17` | `(allow andrixd andrix_owner (process (dyntransition)))` |

The independent review checked every witness against the rules in all three sources. All 28
violate their own rule, and only rule 21's witness also violates another rule, rule 11. Rule 4's
witness avoids rule 8. Rule 10's and rule 19's avoid rule 26, because `no_x_file_perms` is
`{ execute execute_no_trans }`.

### Qualification and failing controls

- The 28 mutants each fail.
- A rule naming an undefined type, an undefined class, and an undefined permission each fails
  step D through its warning.
- An empty rule file fails (`system/sepolicy/tools/sepolicy-analyze/neverallow.c:438`).
- A witness entry whose literal text no longer matches its source line, a source rule without an
  entry, and an entry whose expansion is missing from the expanded rule file each fail step C. So
  does a fixture policy directory or patch with one more literal rule and no entry.
- Hash files that differ, or a hash computed again that differs, fail step A. So does a fixture odm
  image carrying `/odm/etc/selinux/precompiled_sepolicy`.
- A recompiled control whose decompiled text differs from the loaded policy's fails step E. Failing
  control: one CIL file left out of the recompilation.
- A policy without `andrix_owner` fails step B. The unmodified GrapheneOS release is such a policy.
- A mutant that adds an `allow` breaking an AOSP rule fails step F. The same `allow` added to the
  official policy as well is reported as a vendor finding instead.
- A mutant that adds an `allowx` for `ioctl TIOCSTI` on `andrix_owner_devpts` fails step G.
- A mutant that adds one `allowx` inside a vendor rule fails step G. The witness takes one member of
  the rule's source attribute and an ioctl the rule forbids, for example `0x8008` on
  `gpu_device_202604` for the rule at
  `vendor/adevtool/vendor-skels/google_devices/caiman/sepolicy/vendor/sepolicy_ext.cil:2426`. An
  `allowx` violates nothing unless its source already holds the `ioctl` permission on that target
  (`external/selinux/libsepol/src/assertion.c:409-417`). The member is therefore chosen from the
  module generated at stage 6 among those that already hold it, or the mutant adds that `allow` with
  the witness.

Stage 1 corpus. Before a caiman build exists, the tool runs in a separate corpus mode on the
sealed image of the Andrix Cuttlefish product, built from the pinned tree with the owner session and
lifecycle on. Its Andrix rules are the same, and its build checked neverallows. Corpus mode can
never pass the gate. Its only verdicts are CORPUS and REFUSE, and it never exits 0. It departs from
the gate only where the corpus is not a caiman image:

- It reads the precompiled policy that init would load, from odm before vendor
  (`system/core/init/selinux.cpp:141-147`), and records a `userdebug_plat_sepolicy.cil` instead of
  refusing it.
- Step C checks the `user` expansions against the expanded rule file, and the variant's expansions
  against the witness table.
- Step D runs the variant's rules, which must pass. For a `userdebug` corpus it also runs the `user`
  rules, which must fail with exactly `allow overlay_remounter andrix_owner_entry:file { execute };`.
- Step G runs on the corpus files alone and must report no violated rule. Step F does not run,
  because no official policy exists for this product.

The hash pairs of step A, and steps B and E, run as in the gate. A corpus run shows that the tool
works on a real policy. It shows nothing about a caiman build, and the gate that a caiman build
must pass does not change. The images are EROFS, so they are read with `fsck.erofs`, not
`debugfs`.

### Unverified until a caiman build

- That the expanded rule file is built and contains the 28 expected expansions.
- That the recompiled control passes and its decompiled text equals the loaded policy's byte for
  byte. If the two differ only in the order of statements, that is a review finding, not a pass.
- That the installed platform CIL files carry their neverallow statements. On the Cuttlefish
  corpus they do, and its recompiled control is byte for byte the loaded policy. Neither says
  anything yet about caiman.
- Which AOSP rules the extracted vendor policy breaks. The first run on the official release lists
  them.

## 3. Device services overlay

### What the sources show

- The framework default is an empty array
  (`frameworks/base/core/res/res/values/config.xml:5603-5605`). System server starts each listed
  class in order and only reports a failure
  (`frameworks/base/services/java/com/android/server/SystemServer.java:3286-3299`).
- No file in adevtool at either tag names `config_deviceSpecificSystemServices`. That covers the
  caiman record and GrapheneOS's zumapro overlay
  (`vendor/adevtool/config/mk/google_devices/platform/zumapro/gos-overlays/GosOverlay/res/values/values.xml:1-15`).
  A search of `frameworks/base/core/res`, `device`, `vendor`, `packages`, `build/make/target` and
  `hardware` finds it only in the framework default and in an unrelated automotive product under
  `device/google/sdv`.
- adevtool converts every stock overlay into a source overlay and keeps every value unless a filter
  excludes it (`vendor/adevtool/src/blobs/overlays2.ts:13-40`,
  `tools/arsclib/java/org/grapheneos/arsclib/ApkConverter.java:669-680`). No filter names the array
  (`vendor/adevtool/config/device/common/overlay-inclusion.yml`,
  `vendor/adevtool/config/device/common/overlay-removal.yml`). The 49 generated overlays
  (`vendor/adevtool/vendor-skels/google_devices/caiman/overlays/overlay-modules.txt`) carry no value
  for it. The stock framework overlays become `framework-res__caiman__auto_generated_rro_product`
  and `..._vendor` (`vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:222-272`).
- The only prebuilt package with "Overlay" in its name is `EuiccGoogleOverlay`, an app import in
  `system_ext/priv-app`, not in an overlay directory
  (`vendor/adevtool/vendor-skels/google_devices/caiman/proprietary/Android.bp:387-396`, path at
  `:390`). Its target cannot be read without the stock image. Inference: it overlays the eSIM app,
  not `android`.
- Inference: the effective caiman array at 2026100600 is empty, as on Cuttlefish. Every source
  overlay and recorded prebuilt that could be read leaves it unset, and only the target of
  `EuiccGoogleOverlay` is unread. Andrix's overlay replaces it with one entry
  (`owner/platform/overlay/res/values/config.xml:4-6`). The overlay is static, priority 999, on the
  product partition (`owner/platform/overlay/AndroidManifest.xml:7`,
  `owner/platform/overlay/Android.bp:5`).

### Design

Keep the overlay with its single entry, and make the merge a checked fact for each build:

- A check, `scripts/pixel/overlay_services.py`, reads the images of the install zip. It takes
  `framework-res.apk` and every APK on the system, system_ext, product, vendor and odm images,
  wherever it sits, so an overlay outside the overlay directories is found too. It reads each
  manifest with `aapt2 dump xmltree`. Every APK whose manifest declares an overlay of `android`,
  static or not, is read for the array with `aapt2 dump resources`. The check passes only when the
  framework value is empty, Andrix's overlay is the only overlay that defines the array, and its
  value is exactly the Andrix service.
- If another overlay ever defines the array, the check fails and prints the union in a fixed order:
  the device's entries first, Andrix's last. Adopting that union is a reviewed change at that tag.
  It puts the union into Andrix's overlay and extends the check to accept exactly that value, and
  only where Android's overlay ordering gives Andrix's overlay precedence over the other definer.
  Until then the check needs no precedence rules, because it refuses any second definition.
- The manifest comment (`owner/platform/overlay/AndroidManifest.xml:5-6`) is updated to name the
  check instead of Cuttlefish only.
- Alternatives not chosen. A frameworks/base patch that starts the service adds carried framework
  code. A system service inside an APEX would move the jar into `dev.andrix.usr` and is a larger
  redesign.

### Qualification and failing controls

- A fixture with a second overlay that targets `android` and defines the array fails.
- The same fixture placed in a `priv-app` directory instead of an overlay directory fails too.
- A fixture framework with a nonempty default fails.
- An image without Andrix's overlay, or with a different value in it, fails.
- At stage 8, a targeted reading shows the lifecycle service registered (the service list over adb,
  within decision 6).

### Unverified until a caiman build or session

- That the overlays generated at stage 6 equal the record. The check then reads the target of
  `EuiccGoogleOverlay` from its manifest.
- That `OwnerLifecycleService` starts on the phone.

## 4. Owner resource controls

### What the sources show

- Andrix writes the three limits from init (`owner/andrixd.rc:13-17`). `andrixd` then requires its
  own `0::/system/uid_7500/pid_N` cgroup on a cgroup2 file system, the exact values of `memory.max`,
  `memory.swap.max` and `memory.oom.group`, and parents it cannot write
  (`owner/native/guards.cpp:105-125`).
- `andrixd` runs with the task profile `SCHED_SP_BACKGROUND` (`owner/andrixd.rc:27`). AOSP defines
  it as an aggregate of `HighEnergySaving`, `LowIoPriority` and `TimerSlackHigh`
  (`system/core/libprocessgroup/profiles/task_profiles.json:712-713`). libprocessgroup loads the
  system profiles, then the API level file, then `/vendor/etc/task_profiles.json`, then the
  system_ext file, so a vendor file may redefine any of these profiles
  (`system/core/libprocessgroup/task_profiles.cpp:914-944`).
- The caiman product installs the stock vendor `task_profiles.json`
  (`vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:1415`). Its hash is in
  `vendor/adevtool/vendor-specs/google_devices/caiman.yml:3923`. It installs no vendor
  `cgroups.json`, because adevtool's inclusion list names only the profiles
  (`vendor/adevtool/config/device/common/file-inclusion.yml:1332`). The vendor profile content is
  not in the tree.
- libprocessgroup reads `/etc/cgroups.json`, then `/etc/task_profiles/cgroups_<first API level>.json`
  if present, then `/vendor/etc/cgroups.json` if present
  (`system/core/libprocessgroup/util/util.cpp:189-211`). No file of the API level form exists in
  `system/core` or `build/make/target` at the tag.
- AOSP's `cgroups.json` at the tag puts memory on cgroup v2 at `/sys/fs/cgroup`, with activation
  needed, a maximum activation depth of 3, and marked optional
  (`system/core/libprocessgroup/profiles/cgroups.json:25-43`). The v1 list has no memory controller.
- Init mounts cgroup2 (`system/core/libprocessgroup/setup/cgroup_map_write.cpp:137-168`), activates
  memory at the root (`:171-180`), and creates `apps` and `system` with all controllers activated
  (`:256-269`, `:271-308`). A process of a UID below 10000 lives in
  `/sys/fs/cgroup/system/uid_<uid>/pid_<pid>`
  (`system/core/libprocessgroup/task_profiles.cpp:140-157`). Creating the UID directory activates
  controllers in it (`system/core/libprocessgroup/processgroup.cpp:691-735`,
  `system/core/libprocessgroup/util/util.cpp:234-254`). Inference: `system/uid_7500` has depth 2,
  below 3, so each `pid_N` below it gets the memory files
  (`system/core/libprocessgroup/util/util.cpp:179-187` and `:240`).
- The v1 path for each app's memory group runs only with `ro.config.per_app_memcg` or a low RAM
  device (`system/core/libprocessgroup/processgroup.cpp:176-179`, `:747-760`). Caiman's generated
  property files set neither (`vendor/adevtool/vendor-skels/google_devices/caiman/sysprop/vendor.prop`,
  `product.prop`, `system_ext.prop` in the same directory).
- Kernel: `CONFIG_CGROUPS=y` (`kconfig:185`), `CONFIG_MEMCG=y` (`kconfig:188`) and `CONFIG_SWAP=y`
  (`kconfig:916`). The built in command line disables only pressure files with
  `cgroup_disable=pressure` (`kconfig:533`). The board adds `cgroup.memory=nokmem`
  (`vendor/adevtool/vendor-skels/google_devices/caiman/BoardConfig.mk:47`), which turns off kernel
  memory accounting only. `System.map` holds `memory_max_write`, `swap_max_write`,
  `memory_oom_group_write`, `swap_files` and `mem_cgroup_swap_init`. `CONFIG_IKCONFIG_PROC=y`
  (`kconfig:165`).
- `shell` may read cgroup v2 files (`system/sepolicy/private/shell.te:447`).

### Design

No change to the vendor side. Andrix relies on the platform's cgroup layout. Two additions:

- A build check, `scripts/pixel/owner_cgroups.py`, on the install zip's images from stage 6. It
  requires:
  - in `/system/etc/cgroups.json`, memory on cgroup v2 with a maximum activation depth of at least 3;
  - no `/vendor/etc/cgroups.json`, or one that leaves memory with those properties;
  - no `/system/etc/task_profiles/cgroups_*.json` that moves memory;
  - in the task profile files, read in the order libprocessgroup loads them, which is the system
    file, the API level file, the vendor file and the system_ext file
    (`system/core/libprocessgroup/task_profiles.cpp:914-944`), no definition of
    `SCHED_SP_BACKGROUND` or of a profile it aggregates that acts on the memory controller or joins a
    cgroup on cgroup v2, because either could move `andrixd` out of its own directory or change its
    limits;
  - in the vendor init scripts under `/vendor/etc/init/` and its subdirectories, no line that writes
    `cgroup.subtree_control` or a `memory.` file, and none that mounts a cgroup file system with the
    memory controller;
  - neither `ro.config.per_app_memcg` nor `ro.config.low_ram` true in any `build.prop`;
  - `CONFIG_MEMCG=y` and `CONFIG_SWAP=y` in the configuration embedded in the `boot.img` kernel;
  - no `cgroup_disable` naming memory and no `swapaccount=0` in the boot and vendor boot command
    lines or boot configuration.
- Targeted phone readings, which are what would show it on the phone. They run over adb shell at
  stage 7 on GrapheneOS, which has the same kernel and vendor image, and again at stage 8:
  - `cat /sys/fs/cgroup/cgroup.controllers` and `cat /sys/fs/cgroup/system/cgroup.subtree_control`
    both list `memory`;
  - `grep cgroup /proc/mounts` shows the cgroup2 mount and no v1 memory mount;
  - for a running service of a system UID, its directory under `/sys/fs/cgroup/system/uid_1000/`
    holds `memory.max`, `memory.swap.max` and `memory.oom.group`;
  - `zcat /proc/config.gz | grep MEMCG`.

  On Andrix the deciding reading is `andrixd` passing its own admission
  (`owner/native/guards.cpp:105-125`).

### Qualification and failing controls

Fixtures each fail the build check: memory listed under v1 `Cgroups`, a maximum activation depth of
2, a vendor `cgroups.json` that adds memory on v1, a vendor `task_profiles.json` that redefines
`HighEnergySaving` to join a memory cgroup, a vendor init script that writes `memory.max`, a kernel
configuration without `CONFIG_MEMCG`, a command line with `cgroup_disable=memory`, and
`ro.config.per_app_memcg=true`.

### Unverified until a caiman build

- What the vendor task profiles and vendor init scripts contain. The stage 6 images show both, and
  the build check reads them there.

### Unverified until a session

- The readings themselves. The conclusion above is an inference from source and configuration.

## 5. Product identity

### What the sources show

- The generated product names brand `google`, model `Pixel 9 Pro`, manufacturer `Google`, device and
  name `caiman`, and the five attestation values
  (`vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:20-30`). adevtool copies them from
  the stock product partition's properties (`vendor/adevtool/src/build/make.ts:203-214`).
- The fingerprint is `brand/product/device:version/BUILD_ID/BUILD_NUMBER:variant/tags`
  (`build/make/core/config.mk:1369-1371`). Every partition's `build.prop` gets brand, device,
  manufacturer, model and name from the same values. Every partition except system also gets the
  attestation values (`build/soong/scripts/gen_build_prop.py:130-147`). A user build shows
  `ro.build.display.id` as the build number and its keys (`:191-196`). The build number becomes
  `ro.build.version.incremental` at build time (`:172`, `:197`).
- Attestation reads `ro.product.<x>_for_attestation` first and `ro.product.vendor.<x>` after
  (`frameworks/base/core/java/android/os/Build.java:1987-1992`). The KeyMint test suite uses the
  same order
  (`hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintAidlTestBase.cpp:2860-2885`).
- Code that matches on these properties:
  - IMS user agent templates: `#MANUFACTURE#` becomes `Build.MANUFACTURER`, `#MODEL#` becomes
    `Build.MODEL` and `#BUILD#` becomes `Build.ID`
    (`packages/modules/ImsStack/java/src/com/android/imsstack/core/config/CarrierConfig.java:1792-1834`).
    142 of caiman's carrier settings files set `ims.ims_user_agent_string`
    (`vendor/adevtool/vendor-skels/google_devices/caiman/proprietary/product/etc/CarrierSettings/`),
    with templates such as `#MANUFACTURE# #MODEL# #BUILD#`. Inference: the Shannon IMS app on caiman
    fills them the same way.
  - The MMS user agent and profile URL insert `Build.MODEL`
    (`packages/services/Telephony/src/com/android/phone/PhoneInterfaceManager.java:10636-10672`).
  - GrapheneOS Settings picks the Pixel feature set when `Build.MANUFACTURER` is `Google`
    (`packages/apps/Settings/src/com/android/settings/SettingsApplication.java:154`). A display
    control repeats "PixelDisplayService's check" on the manufacturer
    (`packages/apps/Settings/src/com/google/android/settings/display/HighEmissionFrequencyController.kt:17-20`).
    Fingerprint enrollment tests `Build.BRAND`
    (`packages/apps/Settings/src/com/android/settings/biometrics/fingerprint/feature/SfpsEnrollmentFeatureImpl.java:105`).
    The battery charge limit tests the manufacturer
    (`frameworks/base/core/java/android/ext/power/BatteryChargeLimit.java:27-29`).
  - GrapheneOS's carrier configuration app reads no `Build` field and no product property. It
    matches the SIM (search of `packages/apps/CarrierConfig2`).
  - Firmware is registered on the device name
    (`vendor/adevtool/vendor-skels/google_devices/caiman/Android.mk:6`). Hardware variant
    configuration is keyed by SKU (`vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:216`).
  - GrapheneOS advertises `grapheneos.version` when the incremental parses as an integer
    (`frameworks/base/services/core/java/com/android/server/SystemConfig.java:2163-2170`).
  - GrapheneOS's App Store gates at least one OS component on that feature. The build script of the
    sandboxed Google Play compatibility library writes
    `requiredSystemFeatures = ["grapheneos.version >= $OS_BUILD_NUMBER"]` beside the signed APK
    (`packages/apps/GmsCompat/lib/build.sh:23-28`). That component is signed with the OS key
    `gmscompat_lib` (`packages/apps/GmsCompat/lib/Android.bp:4`), which release signing takes from
    the key directory given with `-d`
    (`build/make/tools/releasetools/sign_target_files_apks.py:1521`). The key is one of the release
    keys (`script/common.sh:155-165`), so on this phone it is a workshop key.
  - Remote key provisioning sends `Build.FINGERPRINT` in its requests
    (`packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java:149`).
    By default the requests go to GrapheneOS's proxy
    (`frameworks/base/core/java/android/ext/settings/RemoteKeyProvisioningSettings.java:28-34`).
- `BUILD_ID` must be the stock build
  (`vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:6-8`). Andrix's install zip checker
  requires a caiman `release-keys` fingerprint naming one stock build, and accepts any build number
  of a plain form in an Andrix zip (`scripts/pixel/install_zip.py:65-67`, `:600-608`).
- Stop point 1 records the build number shown in Settings. The session checker parses it as a
  GrapheneOS release number (`scripts/pixel/version_criterion.py:297`, `:362`), which refuses
  anything that is not ten digits (`scripts/pixel/caiman.py:50-52`).
- The setup wizard greets with "Welcome to GrapheneOS"
  (`packages/apps/SetupWizard2/res/values/strings.xml:5`).
- GrapheneOS's FAQ, anchor `trademark`, asks derivatives that are published or redistributed to
  replace the GrapheneOS branding with their own, and says forks should not be presented as
  GrapheneOS.

### Design

- **Hardware identity unchanged.** Brand `google`, manufacturer `Google`, model `Pixel 9 Pro`,
  device `caiman`, and all five attestation values, exactly as generated. They describe the hardware
  truthfully. Changing brand or manufacturer would switch off Pixel features in Settings and the
  charge limit. Changing the model would change the MMS headers carriers receive. Inference: changing
  model or manufacturer would also change the IMS user agent on caiman.
- **Software identity Andrix's own.**
  - `PRODUCT_NAME := andrix_caiman`, required anyway by item 1. It appears in `ro.product.name`, the
    fingerprint's second field, `ro.build.flavor` and the description.
  - `BUILD_NUMBER` of the form `andrix.<base tag>.<n>`, for example `andrix.2026100600.1`, where n
    counts Andrix builds on that base. It is never a GrapheneOS release number. The release wrapper
    of item 6 derives it before the build, from the verified base tag and a counter in the release
    records. Settings then shows `andrix.2026100600.1 release-keys`.
  - The fingerprint becomes
    `google/andrix_caiman/caiman:17/CP3A.261005.005/andrix.2026100600.1:user/release-keys`. It
    differs from Google's and from GrapheneOS's. It passes `scripts/pixel/install_zip.py:66-67`.
  - The phone then advertises no `grapheneos.version`, which is honest, because it is not that
    GrapheneOS release. This also follows GrapheneOS's branding position, since the phone's build
    identity does not present it as GrapheneOS. The setup text still names GrapheneOS, which owner
    question 4 covers.
- **Consequences the owner reviews with the identity.**
  - The fingerprint is unique to this phone, because only this phone runs Andrix caiman builds.
    Every app can read it, and remote key provisioning sends it through GrapheneOS's proxy.
  - The sandboxed Google Play compatibility library cannot update from the App Store. The App Store
    finds no `grapheneos.version`. An update signed with GrapheneOS's key could not replace the copy
    signed with the workshop key anyway, because the package manager checks an update's signature
    against the installed version
    (`frameworks/base/services/core/java/com/android/server/pm/InstallPackageHelper.java:1887-1923`).
    It therefore moves only with Andrix builds. That bears on push notifications, which decision 4
    asks about.
  - Interface text that names GrapheneOS, such as the setup greeting, is owner question 4 below.
    GrapheneOS's branding position makes the change required before any published build.
- **A design item for the Pixel checkers.** The session checker must learn the Andrix build number.
  On a phone that runs Andrix, stop point 1 reads a build number such as `andrix.2026100600.1`.
  `scripts/pixel/caiman.py:50-52` refuses it today, so a session that passes it to the checker is
  refused, which fails closed. The change: when the session chain records an Andrix build as the
  last image written, the checker accepts a build number of the Andrix form only if it equals that
  build's number. The phone's release stays what the chain carries, where an Andrix build counts as
  its base tag. The checker never reads an Andrix build number as a release number. This is a
  change to `scripts/pixel`, designed here and not made.

### Qualification and failing controls

- A check, `scripts/pixel/product_identity.py`, reads every partition's `build.prop` and the vbmeta
  properties. It requires the hardware values above, product name `andrix_caiman`, attestation
  values equal to those in the generated `caiman.mk` at the tag, an incremental of the Andrix form
  whose base tag equals `com.andrix.build.base_tag`, and fingerprints that agree across partitions.
- Failing controls: the official GrapheneOS zip, with product `caiman` and a ten digit incremental,
  a `build.prop` with brand `Andrix`, and one changed attestation value.
- For the checker change: a session that records an Andrix build and then reads a different Andrix
  build number is refused, and so is an Andrix build number given where no Andrix build was written.
- On the phone, essentials items 2 and 4 cover carrier behaviour: VoLTE registration and MMS.

### Unverified until a session

- Whether closed vendor or carrier code matches `ro.product.name` or the incremental. Readable
  sources show none.
- Whether the remote provisioning service accepts requests with the Andrix fingerprint. Inference:
  the request is checked against device keys, and GrapheneOS's own incremental already differs from
  stock, but the product name field is new.
- Whether the App Store offers updates of the presigned apps to a phone without
  `grapheneos.version`, and whether any prebuilt component reads `grapheneos.version`. Prebuilt APKs
  cannot be searched as source. Stage 8 checks the App Store if the owner keeps it (owner question
  3).

## 6. Signing and updates

### What the sources show

- `script/generate-release.sh` takes `DEVICE BUILD_NUMBER` (`:7-12`) and decrypts `keys/$DEVICE`
  into tmpfs (`:14-21`). It reads `releases/$BUILD_NUMBER/$DEVICE-target_files.zip` and
  `$DEVICE-otatools.zip` (`:27-32`), selects caiman's steps (`:66-72`), sets the vbmeta key and
  algorithm (`:77-78`), and signs with `-o -d "$KEY_DIR" --avb_vbmeta_key` and a list of APEX keys
  (`:80-184`). From the same signed target files it then writes the OTA, the image zip, the factory
  images and the install zip, and signs the install zip with SSH when `id_ed25519` exists
  (`:186-209`).
- `script/finalize.sh:16-17` copies `$TARGET_PRODUCT-otatools.zip` and
  `$TARGET_PRODUCT-target_files.zip`. With product `andrix_caiman`, `generate-release.sh caiman`
  finds neither file.
- `decrypt-keys` and `encrypt-keys` handle only the keys in `signing_keys`
  (`script/common.sh:155-165`) plus `avb.pem`.
- In GrapheneOS's signing tool, an APK whose certificate no mapping covers is dropped from the key
  map so signing fails (`build/make/tools/releasetools/sign_target_files_apks.py:328-331`,
  `:523-526`). An APEX keeps its own key paths unless `-k`, `--extra_apks` or
  `--extra_apex_payload_key` overrides them (`:336-403`). With `-o`, signing replaces the
  certificates that verify OTA packages, and the payload verification key, with the keys of the
  target files as `-d` remaps them
  (`build/make/tools/releasetools/sign_target_files_apks.py:65-71`, `:1123-1124`).
- The otatools package includes every `.pk8`, `.pem` and `.avbpubkey` under `vendor/`
  (`build/soong/ui/build/finder.go:123-133`, `:232-236`,
  `build/make/tools/otatools_package/Android.bp:221-236`). The release script unpacks it and signs
  from inside it (`script/generate-release.sh:32-33`). Inference: with the lab keys present in
  `vendor/andrix/keys` at build time, an APEX left out of the script would be signed with the lab
  payload and container keys, without any error.
- `ReplaceCerts` rewrites certificates in `mac_permissions.xml` only for `-d` and `-k` pairs, and
  skips silently when a certificate file is missing
  (`build/make/tools/releasetools/sign_target_files_apks.py:1199-1253`, used at `:846-848`).
  `--extra_apks` does not touch `mac_permissions.xml`.
- The console APK and the APEX container use the lab certificate (`owner/Android.bp:406`,
  `apex/dev.andrix.usr/Android.bp:40-41`, `keys/Android.bp:1-10`). Console trust maps that
  certificate (`owner/sepolicy/keys.conf:3-4`, `owner/sepolicy/mac_permissions.xml:4-8`).
- `--avb_vbmeta_extra_args` is appended to `avb_vbmeta_args` only together with `--avb_vbmeta_key`
  (`build/make/tools/releasetools/sign_target_files_apks.py:1445-1475`, option at `:1867-1868`).
  Signing rebuilds the images (`:2079-2085`), and `BuildVBMeta` adds those arguments
  (`build/make/tools/releasetools/common.py:1675-1699`). The value is split with `shlex`
  (`build/make/tools/releasetools/common.py:1677`).
- `BUILD_NUMBER` is fixed when the build runs. It becomes the incremental of every partition and a
  field of the fingerprint (`build/soong/scripts/gen_build_prop.py:172`, `:197`,
  `build/make/core/config.mk:1370`). The release script receives it as an argument only to find its
  inputs and name its outputs.
- The Updater is included only with `OFFICIAL_BUILD=true`
  (`build/make/target/product/media_system.mk:39-41`), and points at GrapheneOS's server
  (`packages/apps/Updater/res/values/config.xml:3`). The build guide warns that a build with other
  keys must not use that server. Andrix's guard covers only the Cuttlefish product
  (`products/andrix_gos_cf_arm64_only_phone.mk:204-211`).
- The rollback index is the platform security patch timestamp
  (`build/make/target/board/BoardConfigMainlineCommon.mk:38`, included through
  `vendor/adevtool/config/mk/google_devices/platform/zumapro/BoardConfig-common.mk:1`). The vendor
  and boot patch levels equal the platform level
  (`vendor/adevtool/config/mk/google_devices/common/device-common.mk:7` and `:10`). Each
  partition's patch level is a vbmeta property (`build/make/core/Makefile:4887-4971`).
- `scripts/pixel/install_zip.py` takes the base tag from the single signed
  `com.andrix.build.base_tag` property (`:591-597`) and refuses every Andrix zip until the workshop
  key digest is recorded (`:55`). Its Andrix reader needs an install zip: it reads `avb_pkmd.bin`,
  `vbmeta.img`, `android-info.txt`, `flash-all.sh` and the firmware images (`:568-584`).
- The version criterion knows three kinds of image: a GrapheneOS install zip, an Andrix install zip
  and Google's stock image (`scripts/pixel/version_criterion.py:50`, `:1112`). An OTA is none of
  them, so stop point 4 refuses an OTA today.
- An OTA for caiman writes firmware partitions as well as the OS. Beside the OS images,
  `AB_OTA_PARTITIONS` lists abl, bl1, bl2, bl31, gcf, gsa, gsa_bl1, ldfw, modem, pbl and tzsw
  (`vendor/adevtool/vendor-skels/google_devices/caiman/BoardConfig.mk:68-92`).
- The tree carries tools that read an OTA. `check_ota_package_signature.py` verifies the package
  signature and the payload signatures against a certificate
  (`build/make/tools/releasetools/check_ota_package_signature.py:52`, `:141-167`). `ota_extractor`
  is a host tool that extracts partition images from a payload
  (`system/update_engine/Android.bp:1470-1490`).
- The source verifier is pinned to the 2026081300 anchor only, and a new tag needs a pin review
  (`scripts/proof/grapheneos_source.md:3-4`, `:30`).

### Design

**a. What the release script needs.** A reviewed Andrix patch to GrapheneOS's `script` project,
`andrix-release`, in the patch directory for the tag, with a profile and an inspector like the other
patches. It changes `generate-release.sh` only:

- it reads `andrix_${DEVICE}-target_files.zip` and `andrix_${DEVICE}-otatools.zip`, which
  `finalize.sh` writes for `TARGET_PRODUCT=andrix_caiman`. The outputs keep their `caiman-` names,
  which `scripts/pixel/install_zip.py` expects;
- `sign_target_files_apks` gets four more arguments:
  - `-k vendor/andrix/keys/dev.andrix.usr="$KEY_DIR/releasekey"`, which signs the console APK and
    rewrites its certificate in `mac_permissions.xml`. The rewrite is skipped silently when the old
    certificate file is missing from the unpacked tools
    (`build/make/tools/releasetools/sign_target_files_apks.py:1227-1231`), so the check after
    signing must catch it;
  - `--extra_apks dev.andrix.usr.apex="$KEY_DIR/releasekey"`;
  - `--extra_apex_payload_key dev.andrix.usr.apex="$KEY_DIR/avb.pem"`, as for every GrapheneOS APEX;
  - `--avb_vbmeta_extra_args "--prop com.andrix.build.base_tag:$ANDRIX_BASE_TAG"`;
- it refuses to run unless `ANDRIX_BASE_TAG` is set and is a release number ending in `00`. Because
  that value is split into `avbtool` arguments, this check also keeps any other flag out.

**b. Where the base tag and the build number come from.** A wrapper,
`scripts/release/caiman_release.py`, derives both and never accepts either as an argument. It runs
in two steps.

Before `m`, its `prepare` step:

1. verifies the tree's signed manifest tag with the pinned allowed signers and pinned verification
   settings, as `scripts/pixel/version_criterion.py` does for release tags;
2. checks every project at the manifest's revisions with the source verifier, once that verifier has
   a reviewed pin for 2026100600;
3. checks the tag's base record (`upstream/bases/<tag>.json`) and its adevtool record against the
   tree;
4. derives `BUILD_NUMBER` as item 5 describes, writes it into a pending release record, and prints
   it for the build. The build runs with exactly that `BUILD_NUMBER`.

After the build, its `release` step:

1. reads the pending record and checks the target files against it. The `BUILD_ID` must equal the
   record's stock build, and the incremental in every partition's `build.prop` inside the target
   files must equal the derived build number. A mismatch stops the wrapper before any signing;
2. runs `finalize.sh` and the patched script with the derived values;
3. reads the produced vbmeta and confirms exactly one `com.andrix.build.base_tag` equal to the
   derived tag;
4. completes the release record with the SHA-256 of the signed target files and of every artifact
   made from them, the OTA and the install zip among them.

The vbmeta property is therefore added at the `sign_target_files_apks` call of the release script
(`script/generate-release.sh:80`), from a value only verification code produced. If the build ran
with another number, `scripts/pixel/product_identity.py` of item 5 would refuse the result anyway,
so a late number fails closed. The early derivation makes the build pass when it should.

**c. Console trust.** The console uses the workshop release key, through the `-k` mapping above.
That keeps the key set as the build guide lists it, as the plan's "Boot and trust in workshop mode"
intends. "Settled and chosen" below records the choice.

**d. The `OFFICIAL_BUILD` guard** moves into `andrix.mk`, so every Andrix product stops when
`OFFICIAL_BUILD=true`. The unmodified GrapheneOS comparison build does not inherit `andrix.mk` and is
unaffected.

**e. Updates that keep data.** Before any stage 9 session, an admission check decides which update
package the session may sideload. It follows rule 4 of the plan's
[rules](2026-10-09-caiman-workshop-phone.md#rules), which applies the same full update twice.

1. **One package, once per session.** The check compares the package with the Andrix build that the
   session chain records as installed at the session's start. It requires the same workshop public
   key, a rollback index not lower, no `com.android.build.*.security_patch` value lower, a base tag
   not older, and a later build date. It then writes the package's SHA-256 into the session record.
   For rule 4's second pass the check accepts that same digest again, still compared with the build
   installed at the session's start, and no other package. Without this, the second pass would meet
   a phone that already runs the new build, and a later build date could not hold. One slot would
   then keep the older bootloader, the state rule 4 exists to remove. Both passes run in one
   session. If a session ends after the first pass, a later session cannot repeat that package,
   because the phone already runs it and a later build date cannot hold. The other slot then waits
   for the next complete flash script or update, a state rule 4 already expects. Inference: the
   update engine refuses an older timestamp unless the package was built for a downgrade.
2. **An OTA reader.** A new reader for the OTA zip verifies the package signature and the payload
   signatures with the workshop release certificate, as
   `build/make/tools/releasetools/check_ota_package_signature.py` does. It
   then extracts `vbmeta` and the firmware images from `payload.bin`, with `ota_extractor` pinned by
   SHA-256 like the other host tools. The payload signature check runs `delta_generator`
   (`build/make/tools/releasetools/check_ota_package_signature.py:157-162`), so it is pinned the
   same way. The extracted `vbmeta` must verify against the workshop key
   recorded for this phone, as an install zip's must. The OTA is signed with the workshop release
   key, and recovery accepts it through the OTA certificates that `-o` replaces
   (`script/generate-release.sh:80`, `:186`).
3. **Firmware equal to the official kit.** Every firmware image from the payload must be byte
   identical to the same partition's image in GrapheneOS's official install zip of the build's base
   tag, unpacked from that kit's bootloader and radio images. The reader then passes the OTA's
   identity to the version criterion as the Andrix reader does for an install zip: base tag, stock
   build, firmware versions and the package's SHA-256. The version criterion gains the OTA as a
   fourth kind of image. Like the Andrix build number, this is a change to `scripts/pixel`,
   designed here and not made.
4. **One source for the OTA and the gated zip.** The OTA and the install zip that passed the gate
   must come from the same signed target files. The check requires both digests in one completed
   release record of the wrapper, and the OTA's `vbmeta` byte identical to the install zip's
   `vbmeta.img`.

Stop point 4 refuses an OTA today, as shown above. So until the reader and the fourth kind of image
exist, this gap fails closed. No update that keeps data can pass the stop points before then.

**f. The comparison build of gate step 2.** It is an unmodified GrapheneOS caiman build with the
official `BUILD_NUMBER`, `BUILD_DATETIME` and `OFFICIAL_BUILD=true`, compared and never flashed. The
patched release script refuses to run without `ANDRIX_BASE_TAG`, and it looks for `andrix_` file
names. So the comparison build is signed by GrapheneOS's unpatched `generate-release.sh` at the tag,
from a separate checkout of the `script` project at the tag's revision, with the workshop key set,
in its own output directory. The workshop keys make its signatures comparable with the Andrix
build's, so the comparison separates build noise from the Andrix delta. It cannot pass either
identity check. Its `avb_pkmd.bin` is not GrapheneOS's published one, and its vbmeta carries no base
tag property. It also carries the Updater, which is one more reason it is never flashed.

**g. The workshop key digest.** The workshop key set is generated at stage 6, with the owner. The
SHA-256 of its `avb_pkmd.bin` is recorded as `WORKSHOP_PKMD_SHA256` right then, before the gate
runs (`scripts/pixel/install_zip.py:53-55`). Until it is recorded, every Andrix zip is refused,
which fails closed.

### Qualification and failing controls

A check after signing, `scripts/pixel/release_keys.py`, on the signed target files and the install
zip:

- the `dev.andrix.usr` payload public key equals the workshop `avb_pkmd.bin`, and its container
  certificate is the workshop release certificate;
- the console APK certificate is the workshop release certificate;
- `system_ext` `mac_permissions.xml` holds that certificate for `dev.andrix.terminal` and no lab
  certificate;
- there is no Updater APK and no `app.seamlessupdate.client` permission file;
- there is exactly one base tag property.

Failing controls:

- Signing without the Andrix arguments stops at the console APK
  (`build/make/tools/releasetools/sign_target_files_apks.py:523-526`). The control expects that
  error.
- An APEX signed with the lab keys is refused.
- `mac_permissions.xml` still holding the lab certificate is refused.
- A vbmeta without the property, or with two, is refused by `scripts/pixel/install_zip.py`. The
  existing test `test_andrix_identity_is_cross_checked` covers this.
- A wrapper run on a tree whose tag does not verify, or whose `BUILD_ID` disagrees with the record,
  is refused.
- A wrapper `release` step on target files whose incremental differs from the pending record is
  refused before signing.
- `andrix.mk` with `OFFICIAL_BUILD=true` stops make. This is a host make test.
- For update admission, each lowered value is refused. A second package in the same session is
  refused. The same digest is accepted for the second pass, and a fixture without that rule refuses
  the second pass, which shows why the rule exists.
- For the OTA reader, a payload whose firmware image differs by one byte from the official kit is
  refused, and so is an OTA whose `vbmeta` differs from the gated install zip's.

### Unverified until a caiman build

- That the lab key files really reach the otatools package and would be used. This is an inference
  from the code above.
- A real signing run, and its duration.
- How the official kit's bootloader and radio images unpack into partition images, and that a full
  OTA payload carries every firmware partition as a whole image. If either fails, the OTA reader
  refuses the OTA.

## 7. Hardware qualification method

The plan's method holds: few flashes, each a wipe, no snapshots, the essentials checklist, emergency
calling never dialed, and recording within decision 6 (the plan's design item 7 and its
[essentials checklist](2026-10-09-caiman-workshop-phone.md#essentials-checklist)). It has these gaps:

1. **The boot state reading.** Item 15 asks for honest boot state, but `getprop` from adb shell
   reads the real value even on GrapheneOS, because the override applies only to app processes
   (item 9). Read `BIONIC_APPCOMPAT_OVERRIDE=1 getprop ro.boot.verifiedbootstate` instead
   (`bionic/libc/system_properties/system_properties.cpp:80-82`). Inference: the GrapheneOS baseline
   prints `green` and Andrix prints `orange`.
2. **adb for readings.** Targeted readings for items 3, 4 and 9 need adb, while item 15 requires USB
   debugging off. The session needs a fixed order: enable, read, revoke the authorization, disable,
   and record the final state. A user build asks for authorization
   (`build/soong/scripts/gen_build_prop.py:335-337`). Whether adb may be used at all is owner
   question 5.
3. **Owner preconditions.** No reading is planned for the owner cgroup files, the lifecycle service
   or `andrixd` admission. Add them as Andrix checks, recorded separately as the plan intends.
4. **Memory tagging.** Andrix native code meets tag checking first on the phone
   (`vendor/adevtool/config/mk/google_devices/common/BoardConfig-armv9.mk:5-15`). Crashes leave
   tombstones, which are logs under decision 6. Running Andrix's native tests where tags are checked
   before stage 6 would find faults earlier. Inference: QEMU's user mode emulation with `-cpu max`
   offers tag checking. This is unverified.
5. **Drain and temperature.** Comparing with the baseline needs a recording method within decision
   6, for example figures the owner reads from Settings.
6. **Recovery.** Stage 9 sideloads through recovery, which the checklist never checks. Add "recovery
   reachable" before the first update session.
7. **Network behaviour.** No observation of the phone's connections is planned (item 8). That needs
   an owner choice, owner question 2.
8. **Apps that refuse `orange`.** The stage 7 baseline cannot show them, because GrapheneOS shows
   apps `green` (item 9). So stage 8 opens each daily app from decision 4 to check for that failure.

### Failing control

The session check refuses a session record whose final state shows USB debugging on, or that lacks
the revoke step after an adb reading. Failing control: a fixture record that ends with USB debugging
on is refused, and the same record with the revoke and disable steps recorded passes.

## 8. Connected policy for Pixel components

### Endpoints from source

| Function | Default | Source | Disposition |
|---|---|---|---|
| Time | `https://time.grapheneos.org/generate_204` | `frameworks/base/core/res/res/values/config.xml:2836-2838`, with HTTPS mode fixed in `frameworks/base/core/java/android/util/NtpTrustedTime.java:317` | GrapheneOS service. `config_ntpServers` still names `time.android.com` (`frameworks/base/core/res/res/values/config.xml:2830-2831`). Inference: unused in HTTPS mode. |
| Connectivity checks | `connectivitycheck.grapheneos.network`, with fallbacks on `grapheneos.online` (FAQ) | `frameworks/base/core/java/android/ext/settings/ConnChecksSetting.java:14-25`, `packages/modules/Connectivity/service/src/com/android/server/ConnectivityService.java:515`, `packages/modules/NetworkStack/res/values/config.xml:16` and `:25` | GrapheneOS. The "Standard" choice is Google's, an owner setting. |
| DNS over TLS probe | `*-dnsotls-ds.dnscheck.grapheneos.org` | `packages/modules/NetworkStack/src/com/android/networkstack/util/DnsUtils.java:53`, `packages/modules/DnsResolver/DnsTlsTransport.cpp:106` | GrapheneOS. With "Standard" checks it uses Google's name (FAQ). |
| Certificate Transparency lists | `gstatic.grapheneos.org/android/certificate_transparency/` | `packages/modules/Connectivity/networksecurity/service/src/com/android/server/net/ct/Config.java:40`, `frameworks/base/core/java/android/ext/settings/CertTransparencyDownloaderSetting.java:18-19` | GrapheneOS mirror. |
| Remote key provisioning | `remoteprovisioning.grapheneos.org/v1`, a proxy to Google | `frameworks/base/core/java/android/ext/settings/RemoteKeyProvisioningSettings.java:15-25`, `packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java:238-245` | Owner approved proxy (`docs/grapheneos-connected-policy-review.md:84-93`). |
| Vendor provisioning hostname | `remote_provisioning.hostname=remoteprovisioning.googleapis.com` | `vendor/adevtool/vendor-skels/google_devices/caiman/sysprop/vendor.prop:94` | Not contacted by default. Required: with it empty, provisioning stops (`packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/provisioner/PeriodicProvisioner.java:108`, `packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/service/RemoteProvisioningService.java:63-66`), and keystore2 treats provisioning as off (`system/security/keystore2/src/remote_provisioning.rs:67-73`). Sent to the proxy as `default_hostname` (`packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java:153-156`). |
| Satellite almanacs | `samsung.psds.grapheneos.org` | `vendor/adevtool/config/mk/google_devices/platform/zumapro/gos-overlays/GosOverlay/res/values/values.xml:12`, `frameworks/base/core/java/android/ext/settings/GnssSettings.java:24-28`, `frameworks/base/services/core/java/com/android/server/location/gnss/GnssConfiguration.java:547-601` | GrapheneOS cache of Samsung's data (FAQ). |
| SUPL | `supl.grapheneos.org:7275`, with cellular and location on | `frameworks/base/core/java/android/ext/settings/GnssSettings.java:13-17`, `frameworks/base/services/core/java/com/android/server/location/gnss/GnssConfiguration.java:522-545` | GrapheneOS proxy. "Standard" is the carrier's or `supl.google.com` (FAQ). |
| GNSS time | none | `vendor/adevtool/vendor-skels/google_devices/caiman/proprietary/vendor/etc/gnss/gps.cfg:1` (`UseNtpForAiding=0`) | Inference: the GNSS daemon fetches no time itself. |
| Widevine provisioning | `widevineprovisioning.grapheneos.org`, when an app plays protected media | `frameworks/base/core/java/android/ext/settings/WidevineProvisioningSettings.java:15-34` | Proxy to a Google backend, allowed as a backend. |
| Network location | off. When on, `gs-loc.apple.grapheneos.org` or Apple | `frameworks/base/core/java/android/ext/settings/NetworkLocationSettings.java:13-17`, `packages/apps/NetworkLocation/src/app/grapheneos/networklocation/ApplePositioningService.kt:100` | Owner choice. |
| Geocoder | off. When on, `nominatim.grapheneos.org` or OpenStreetMap | `frameworks/base/core/java/android/ext/settings/GeocoderSettings.java:12-16`, `packages/apps/NetworkLocation/src/app/grapheneos/geocoder/NominatimGeocoder.kt:196` | Owner choice. |
| App Store | `apps.grapheneos.org` | `build/make/target/product/handheld_product.mk:25`, prebuilt APK, FAQ | GrapheneOS service. Owner question 3. |
| Vanadium | `update.vanadium.app`, `dl.vanadium.app` | FAQ | GrapheneOS service. |
| Info app | `grapheneos.org/releases.atom` when opened | FAQ | GrapheneOS service. |
| Updater | `releases.grapheneos.org` | `packages/apps/Updater/res/values/config.xml:3` | Excluded by item 6. |
| eSIM | off by default. When enabled, carrier servers, and Google only if the carrier uses it (usage guide) | `vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk:280-283`, `vendor/adevtool/vendor-skels/google_devices/caiman/proprietary/Android.bp:387-406`, prebuilt APEX `com.google.pixel.euicc.update`, flags in `vendor/adevtool/vendor-skels/google_devices/caiman/gservices-flags/flags.txt:1-3`, with metrics upload excluded (`vendor/adevtool/config/device/common/pixel.yml:29-38`) | Not readable. Owner choice under decision 4. |
| IMS, MMS, voicemail, RCS, calling over wireless networks | carrier servers, often `3gppnetwork.org` names (FAQ) | the file packages ShannonIms, ShannonRcs and PixelQualifiedNetworksService in `vendor/adevtool/vendor-skels/google_devices/caiman/caiman.mk`, and `config_wlan_data_service_package` in the generated framework overlay | Carrier services the owner uses. |
| Attestation roots URL | `android.googleapis.com/attestation/root` | `vendor/adevtool/vendor-skels/google_devices/caiman/sysprop/product.prop:1`, kept by `vendor/adevtool/config/device/common/sysprop-inclusion.yml:5` | No consumer found in `frameworks`, `packages/modules`, `system/security` or `system/core`. Inference: inert unless an app reads it. Two related Google properties are removed (`vendor/adevtool/config/device/common/sysprop-exclusion.yml:2-3`). |
| Andrix | nothing automatic. `andrixd` holds `inet` for the owner's own work | `owner/andrixd.rc:22` | Owner's explicit work. |

### Comparison with the connected policy review

- The accepted policy forbids automatic direct connections from official images to Google operated
  services and allows Google behind another provider (`docs/architecture.md:95-109`,
  `docs/grapheneos-connected-policy-review.md:57-87`). Inference: every default above that the
  sources show goes to GrapheneOS or to the carrier. The eSIM row cannot be read. The "Standard"
  choices remain owner settings, as GrapheneOS ships them.
- That review's provisioning findings still hold at 2026100600: the override comes before the
  property (`packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java:238-245`).
  New for caiman: the property must stay set, because periodic provisioning and the service stop
  when it is empty, and keystore2 then treats provisioning as off. The emulator profile
  (`init/andrix-cuttlefish-network.rc:6-8`) would therefore switch provisioning off on the phone.
  The same profile also sets `remote_provisioning.tee.rkp_only` to false
  (`init/andrix-cuttlefish-network.rc:7`). Inference: keys that need remote provisioning would then
  be unavailable.
- That review leaves carrier, eSIM and geolocation paths for their own scoped checks
  (`docs/grapheneos-connected-policy-review.md:137-140`). Caiman adds SUPL, almanacs, IMS and
  remote provisioning against real hardware. None of these was exercised by the Cuttlefish baseline
  (`:127-136`).

### Design

- Keep GrapheneOS's defaults and the vendor's provisioning hostname as generated.
- Carry none of the emulator profile: not `andrix-cuttlefish-network.rc` and not the Cuttlefish
  network overlays (`products/andrix_cf_arm64_only_phone.mk:7-11`).
- A check, `scripts/pixel/connected_config.py`, on the install zip's images. It refuses the emulator
  init script and overlays, any init `setprop` of `remote_provisioning.hostname` or of
  `remote_provisioning.tee.rkp_only`, an empty or missing hostname in the vendor `build.prop`, and
  an Andrix patch that touches `frameworks/base/core/java/android/ext/settings/`.
- After review, the endpoint table goes into public documentation as the caiman inventory.
- Observation on the phone needs an owner choice under decision 6, owner question 2. Until then the
  network behaviour of the prebuilt components stays unverified.

### Failing controls

Fixture images each fail the check: one carrying the emulator init script, one whose vendor
`build.prop` lacks the hostname, one whose init script clears it, and one whose init script sets
`remote_provisioning.tee.rkp_only`.

### Unverified until a session

- eSIM: which servers the eSIM components contact when the owner enables eSIM.
- IMS: what the closed IMS and RCS apps contact beyond the carrier's servers.
- Widevine: whether provisioning runs through GrapheneOS's proxy on caiman as the setting says.
- App update checks: what the App Store and Vanadium contact, and how often.
- The phone's connections as a whole, which depend on owner question 2.

## 9. Boot state shown to apps

### What the sources show

- GrapheneOS adds `ro.appcompat_override.ro.boot.verifiedbootstate=green` to the system
  `build.prop` of every user build (`build/soong/scripts/gen_build_prop.py:387-389`).
- AOSP writes the override property area only on eng and userdebug builds
  (`build/make/core/android_soong_config_vars.mk:179-182`, `system/core/init/Android.bp:178-180`).
  GrapheneOS writes it on every build (`system/core/init/property_service.cpp:1409-1414`). Its
  `system/core` commit 62f6dd08, "enable appcompat sysprop overrides", removed the condition.
- Init puts each override into the main area under its own name, and into the override area under
  the target name (`bionic/libc/system_properties/system_properties.cpp:406-430`). A process uses
  overrides when `BIONIC_APPCOMPAT_OVERRIDE` is set at start, or after `EnableOverrides` sets it
  (`:80-82`, `:145-151`). Its lookups then return `ro.appcompat_override.<name>` first
  (`:175-189`). The zygote's reload of the property area calls `EnableOverrides`
  (`bionic/libc/bionic/system_property_api.cpp:134-137`).
- The zygote enables overrides in `BindMountSyspropOverride`
  (`frameworks/base/core/jni/com_android_internal_os_Zygote.cpp:1764-1771`, called at
  `:1906-1908`). Its comment says only `ro.boot.verifiedbootstate` is overridden. Activity manager
  requests it for every app that is not a system app
  (`frameworks/base/services/core/java/com/android/server/am/ProcessList.java:2657`), and only on
  the main zygote path (`:2724-2734`). The WebView zygote and app zygote paths pass no such flag
  (`:2691-2723`). On userdebug and eng builds a DeviceConfig list may add system apps
  (`:2658-2670`).
- So on a GrapheneOS user build these read `green`: every app that is not a system app, which
  means not preinstalled on a read only partition, in processes started from the main zygote. As an
  inference from the inherited environment variable
  (`bionic/libc/system_properties/system_properties.cpp:80-82`, `:150`), so do the programs those
  processes start. System apps, system server, native services, adb shell, and processes started
  from the WebView zygote or an app zygote read the real value.
- The override property has the default context
  (`system/sepolicy/private/property_contexts:168`), which every core domain may read
  (`system/sepolicy/private/coredomain.te:38`).
- Inference: key attestation reports the boot state from the bootloader through KeyMint and not from
  this property, so attestation is honest either way.

### Design

- A reviewed Andrix patch to `build/soong`, `boot-state`, in the patch directory for the tag, deletes
  `build/soong/scripts/gen_build_prop.py:387-389`. It gets a profile and a digest guarded inspector
  like the other patches.
- Init's override area stays. Inference: with no override property defined, lookups fall through to
  the real value (`bionic/libc/system_properties/system_properties.cpp:175-189`).
- Alternatives not chosen:
  - setting the property to `orange` is still an override and is wrong whenever the real state
    differs;
  - reverting only init's change leaves the property in the main area, where the lookup finds it;
  - a product property block list does not exist for system `build.prop` here. Soong builds that
    file without one (`build/soong/Android.bp:226-246`, `build/soong/android/build_prop.go:175-176`).
    That is an inference from these sources.

### Qualification and failing controls

- The gate's content check refuses any property starting with `ro.appcompat_override.` in every
  partition's `build.prop`. Failing control: the official GrapheneOS zip, or the unmodified
  comparison build, is refused.
- The patch inspector accepts only the exact original or adapted bytes, like the other inspectors.
- On the phone: `BIONIC_APPCOMPAT_OVERRIDE=1 getprop ro.boot.verifiedbootstate` reads `orange` on
  Andrix. The same reading on the GrapheneOS baseline at stage 7 is the failing control, and should
  read `green`. A plain `getprop` reads `orange` on both.
- Apps that refuse `orange`. The stage 7 baseline cannot show them, because on GrapheneOS user
  builds apps that are not system apps read `green`
  (`build/soong/scripts/gen_build_prop.py:387-389`). A daily app that refuses `orange` would only
  fail at stage 8. So stage 8
  opens each daily app from decision 4 to check for this failure. The plan's essentials rule and the
  way back catch a failure there, as its
  [essentials checklist](2026-10-09-caiman-workshop-phone.md#essentials-checklist) describes.

### Unverified until a session

- The phone readings above.
- Which apps refuse the real state. The owner accepted that loss. Stage 8 shows it for the daily
  apps.

## What the plan's amendment adopted

The workshop plan was amended from this study in commit 12ac88f. The amendment adopted these points
in the plan's [design items](2026-10-09-caiman-workshop-phone.md#design-items) and
[limits](2026-10-09-caiman-workshop-phone.md#limits):

- **Design item 1.** GrapheneOS's release scripts take the device as an argument but name their
  files after the product, and the build ID is looked up by product name. An Andrix product name
  therefore needs its own handling in the build and release steps, not only in signing. The lab
  vehicles' refusals of other products live in the Cuttlefish product makefile, so they must move to
  a file every Andrix product reads.
- **Design item 2.** adevtool keeps `neverallowx` statements, and `sepolicy-analyze` skips
  `neverallowxperm` rules. So the check adds a `secilc` compilation without `-N`, and a recorded
  warning baseline for the AOSP rules.
- **Design item 3.** At both tags no generated caiman source overlay sets the services array, and
  adevtool's caiman record at 2026100600 shows no prebuilt overlay that sets it either. A build
  check must still refuse any second overlay that sets it.
- **Limits.** The plan now records that this study read the 2026100600 tree. It also records the
  study's trace of which processes get the boot state override, and the rollback index set from
  the security patch timestamp in `build/make/target/board/BoardConfigMainlineCommon.mk:38`. Both
  findings still need a build or a phone session to confirm.

The plan's "Limits" keeps four points listed as unverified on purpose, because a source reading does
not settle them. They are which app processes get the boot state override (item 9), whether caiman
exposes the cgroup2 memory controller that owner sessions need (item 4), whether prebuilt overlays
set the device services array (item 3), and where the build sets the rollback index (item 6). This
document gives the source reading for each. The plan keeps them listed until a build or a phone
session confirms them.

## Open owner questions

These are open. This document proposes an answer for each and decides none. The owner answers them
in review, before the stage each one names.

### 1. The phone's identity (item 5)

Needed before stage 6.

- **A. As designed.** An Andrix product name and build number, with the hardware and attestation
  values as generated. The phone says honestly what it runs. Its fingerprint is unique to this
  phone, every app can read it, and provisioning sends it through GrapheneOS's proxy. The sandboxed
  Google Play compatibility library then moves only with Andrix builds, which matters for push
  notifications.
- **B. GrapheneOS's identity.** The product `caiman` and GrapheneOS's release number. The design
  rules this out. It would present the phone as GrapheneOS, which the plan's design item 5 forbids,
  and GrapheneOS's FAQ asks derivatives not to do that.

Proposal: A, accepting the consequences that item 5 lists. Attestation already sets this phone apart
through its own boot key and its orange state.

### 2. Observing the phone's traffic (item 8)

An owner decision under decision 6. Needed before stage 7.

- **A. None.** Risk 13 in the plan's [risks](2026-10-09-caiman-workshop-phone.md#risks),
  unreviewed network traffic from Pixel components, stays open.
- **B. DNS names only**, at the owner's own resolver, for a short window after setup and before
  personal apps are restored, at both stage 7 and stage 8.
- **C. Full packet capture.**

Proposal: B. It separates system traffic from personal apps, and stage 7 gives the baseline to
compare with.

### 3. Updates from GrapheneOS's App Store

An owner decision, because it lets GrapheneOS's servers deliver code to the phone. Needed before
stage 6, because option B changes the build.

- **A. Keep them.** Vanadium, which is also the system WebView, and Camera, Auditor, PDF Viewer and
  the compatibility configuration app are presigned, so their updates can still install if the App
  Store offers them
  (`external/vanadium/Android.bp:65`, `external/AppStore/Android.bp:7`,
  `external/Camera/Android.bp:6`, `external/Auditor/Android.bp:6`, `external/PdfViewer/Android.bp:6`,
  `external/GmsCompatConfig/Android.bp:5`. `preprocessed: true` implies presigned,
  `build/soong/java/app_import.go:411-415`). Components signed with OS keys follow Andrix builds
  either way.
- **B. Remove the App Store.** Those apps then follow Andrix builds, within decision 7's lag limit.

Proposal: A, because Vanadium's security fixes ship there. Stage 8 then checks that the App Store
offers those updates to a phone without `grapheneos.version`.

### 4. Setup text that names GrapheneOS

An owner choice for this workshop phone only. Needed before stage 6. Before any published build the
change is required, because GrapheneOS's FAQ asks published derivatives to replace its branding.

- **A. Leave it for now**, and change the branding at the release step.
- **B. Patch it now.**

Proposal: A. It avoids one more carried patch on a phone only the owner sees.

### 5. adb during sessions

The targeted readings of items 3, 4, 7 and 9 need USB debugging. The plan's essentials item 15
requires it off. Needed before stage 7.

- **A. Allow it for the fixed reading list only.** Then revoke the authorization, switch it off and
  record that, as item 7 describes.
- **B. Do not allow it.** Those readings then stay unverified on the phone.

Proposal: A.

### Settled and chosen

- **Keep and the compiler payload.** The plan settles this for stages 6 to 8. Its "Inputs" send only
  the normal image composition to the phone. This design reads that as the owner session and owner
  lifecycle composition, so Keep (`ANDRIX_OWNER_KEEP`) and the compiler payload
  (`ANDRIX_OWNER_COMPILER`) stay out of those builds. Adding either later is an owner feature choice
  after stage 8. Fewer parts in the first flash also help the super partition budget.
- **The console key.** An engineering choice within decision 2. The console uses the workshop
  release key. All the workshop keys share one custody and one passphrase, so a separate console key
  would add no protection in workshop mode. A dedicated key would need `signing_keys` extended in
  `script/common.sh:155-165`, which the decrypt and encrypt scripts read. The choice is revisited
  with the locked mode.
