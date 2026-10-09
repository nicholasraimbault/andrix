# Fixtures

Public files from the GrapheneOS source trees at the tags 2026081300 and 2026100600, copied
byte for byte unless a line below says otherwise. They keep their own licenses: `device/common`
is Apache-2.0 and adevtool is MIT. Set `ANDRIX_PIXEL_TREES` to compare them with local trees
again.

- `device-common/generate-factory-images-common.sh` and
  `device-common/clear-factory-images-variables.sh` come from `device/common/`. Both are
  identical at the two tags.
- `adevtool/TAG/config/device/caiman.yml`, `common/gen9pixel.yml` and `common/pixel.yml` come
  from `vendor/adevtool/config/device/`. The tests add a stub for each of the fifteen section
  files that `pixel.yml` includes. In both trees those files set no `device` or `includes` key.
- `adevtool/TAG/config/build-index/build-index-main.excerpt.yml` holds verbatim lines of
  `vendor/adevtool/config/build-index/build-index-main.yml`: one `tegu` entry, one entry with
  only a vendor archive, and the `caiman` entries from CP2A.260605.012 on.
- `adevtool/TAG/vendor-skels/google_devices/caiman/caiman.mk.head` holds the first 8 lines of
  `caiman.mk`, which contain its `BUILD_ID` check. `cmds-for-envsetup.sh` and
  `firmware/android-info.txt` are whole files from the same directory.
- `adevtool/records/TAG.json` is derived from the whole `vendor/adevtool` of each tree.
  Each carries the vendor/adevtool commit of its signed manifest and that manifest's digest,
  as `upstream/bases/TAG.json` pins it. The commits come from the sealed carry report
  `upstream/reports/2026081300-2026100600.json`, and a test checks them against it. The
  trees' Git metadata was outside this environment, so these fixtures carry no `tree_head`,
  which `adevtool_record.py record` adds after checking the tree's HEAD.

SHA-256 of the whole files that the excerpts come from:

```
8a5877b61924542af98f30d9e3233938a211adecbe1b6636c8ef5c641e5ac69a  2026081300 build-index-main.yml
a108c6dd08afe9ad5e3fe09f36ae513b2fac34c7d18a2a66d5a90ebb742933f4  2026100600 build-index-main.yml
7a4c61183dc37c629398f05f2f5b9c1c5628d599dd44a1693dc89728f8a91dbd  2026081300 caiman.mk
8c77c4e636d20206d88da30be96f563f466e95de789f5326ac822f97c93fb463  2026100600 caiman.mk
```

The readings samples, the fastboot and timeout stand-ins, the keys, the images, the install
zips and the signed manifest repository of `world.py` in the tests are synthetic. They are built in a temporary directory for each run and never kept.
