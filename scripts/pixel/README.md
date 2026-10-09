# Pixel 9 Pro workshop phone checkers

These host checkers turn the phone safety rules of the
[caiman workshop phone plan](../../plans/2026-10-09-caiman-workshop-phone.md) into code. They
are part of stage 1. They run on a computer with Python 3 and its standard library. They need
no phone, no build and no download, and none of them contacts a phone or the network.

Every checker refuses what it does not recognise and names the reason. A missing, unknown or
unparsable input is a refusal, never a pass. Exit status 0 means pass or allow. Exit status 1
means refuse or stop, with the reasons in the JSON report.

| File | What it checks |
|---|---|
| `caiman.py` | Shared strict parsers: release numbers, stock build IDs, `android-info.txt`, `caiman-stable` |
| `adevtool_record.py` | Which stock build a GrapheneOS tag uses, as adevtool at that tag records it |
| `version_criterion.py` | Stop points 1, 3 and 4, and the exception "When the OS does not boot" |
| `flash_script.py` | A `flash-all.sh` against the official caiman script (rules 4, 5 and 6) |
| `readings.sh` | The fixed reading script of stop point 2 |
| `readings.py` | Its parser and stop point 3 |
| `install_zip.py` | The checks that need no phone, for a GrapheneOS install zip |

## Use

```sh
P=scripts/pixel
# One record per tag, from a tree checked out at that tag. The tag manifest must hash to the
# digest upstream/bases/TAG.json pins, and vendor/adevtool's HEAD must be its revision.
python3 -B $P/adevtool_record.py record --tree "$TREE" --release 2026100600 --out 2026100600.json
python3 -B $P/adevtool_record.py verify --tree "$TREE" 2026100600.json

# A session record, in the session directory, which holds only session records. Only the very
# first session names the phone's release, as its private record shows it.
python3 -B $P/version_criterion.py start --out sessions/S1.json --session S1 --date 2026-10-09 \
  --first-release 2026081300
# Every later session starts from the newest record and the SHA-256 the owner kept of it. If the
# phone updated itself since, the current stable release starts the record: caiman-stable saved
# right before start, and the build number that stop point 1 recorded from Settings.
curl -o caiman-stable https://releases.grapheneos.org/caiman-stable
python3 -B $P/version_criterion.py start --out sessions/S2.json --session S2 --date 2026-10-10 \
  --previous sessions/S1.json --previous-sha256 "$KEPT_SHA256" \
  --updated-from-stable caiman-stable --build-number 2026100600

# In fastboot mode, the fixed readings with the sealed fastboot, then stop point 3.
sh $P/readings.sh "$SEALED/platform-tools/fastboot" > readings.txt
python3 -B $P/readings.py readings.txt --stage 8 --os-booted yes

# May this image be written now? Exit 0 ALLOW, 1 REFUSE, 3 WAIT for a fresh approval.
python3 -B $P/version_criterion.py decide --record 2026081300.json --record 2026100600.json \
  --manifests "$MANIFESTS" --allowed-signers allowed_signers \
  --image grapheneos --zip caiman-install-2026100600.zip --stable caiman-stable \
  --avbtool "$PINNED_TREE/external/avb/avbtool.py" --session sessions/S2.json \
  --readings readings.txt --stage 8 --os-booted yes --update-pending no --channel stable \
  --security-previews no --approval approval.json

# Gate step 8 at the desk: Google's image or a GrapheneOS kit against a build's base tag.
python3 -B $P/version_criterion.py desk --record 2026100600.json --manifests "$MANIFESTS" \
  --allowed-signers allowed_signers --image stock \
  --zip caiman-cp3a.261005.005-factory-6c37847c.zip --base-tag 2026100600

# A flash script, and a whole install zip.
python3 -B $P/flash_script.py flash-all.sh --android-info android-info.txt
python3 -B $P/install_zip.py --zip caiman-install-2026100600.zip --allowed-signers allowed_signers \
  --release 2026100600 --stable caiman-stable --record 2026100600.json \
  --avbtool "$PINNED_TREE/external/avb/avbtool.py" --simg2img "$TOOLS/simg2img" --lpunpack "$TOOLS/lpunpack"
```

No identity and no session fact is typed.

- **The image.** `--zip` is the image itself. A GrapheneOS install zip is identified by its signed
  build number after every check that needs no phone passes. Google's image is identified by
  the factory digest that adevtool's index records. The decision names the file's SHA-256.
- **An Andrix zip** must also meet four conditions:
  - Its vbmeta must verify against the workshop key whose SHA-256 `install_zip.py` records
    (`WORKSHOP_PKMD_SHA256`).
  - Its `android-info.txt` and fingerprint stock build must equal its base tag's record.
  - Its bootloader and radio images must be byte identical to the verified official kit of
    that tag, given with `--official-kit`.
  - The base tag is the signed vbmeta property `com.andrix.build.base_tag`. Andrix's release
    script must set it from the tag it verified, never by hand.
- **The session record.** `--session` is the checker's own session record. It holds the
  phone's release recorded at the session's start, the releases carried from the previous
  session, and every ALLOWed release. An ALLOW is written into it before the decision returns,
  so before the write runs. Its date is the UTC date of its start, and the approval names that
  date.
- **The session chain.** A phone's session records live in one directory that holds nothing
  else, each as `NAME.json` in the form the checker writes. Each record names the SHA-256 of the
  record before it, and exactly one record, the first, names none. `start` and `decide` verify
  the whole chain and refuse a broken link, a fork where two records name one parent, a second
  first record, a repeated session name, any other file, and a `--previous` or `--session` that
  is not the newest record. Nothing points at the newest record, so after the last `decide` of a
  session the owner keeps its SHA-256 privately, for example from `sha256sum`. The next `start`
  needs it as `--previous-sha256` and refuses a newest record that no longer hashes to it.
- **A phone that updated itself.** After an update between sessions, the readings may match
  none of the carried releases. `start --previous ... --updated-from-stable FILE --build-number B`
  then starts the new record from the current stable release, beside the carried releases. FILE
  is `releases.grapheneos.org/caiman-stable`, saved with `curl -o` right before `start`, and read
  with the strict parser. Its modification time is the fetch time, and a file fetched more than
  15 minutes before the start, or dated after it, is stale and refused. B is the build number
  that stop point 1 records from Settings. The stable release must be newer than every carried
  release, by release number, and B must be that release or its security preview. A B older
  than the stable release means the phone has not updated yet, and the session waits until it
  has. A B newer than it, or naming another release, is refused. The record keeps the stable
  release, the fetch time, B and the file's SHA-256. The release that starts the record is never
  typed, and a phone on the Stable channel runs nothing newer, so the reference can only rise.
- **The known releases** are all of those releases. Each firmware reading must equal the
  version one of them records, or every write is refused. A partial write, a new bootloader
  beside an older radio, still matches, so the whole script can run again.
- **Readings** carry the UTC time `readings.sh` stamped on them. Readings older than the
  session's start or its last ALLOW are refused, and so are readings dated after now and
  readings older than the maximum age at the moment of the decision. The maximum age is the
  plan's 15 minutes. `--readings-max-age` may lower it, from 1 to 15 minutes, never raise it.
- **One decide at a time.** `decide` holds an exclusive lock on the session record from before
  it reads the record until after it writes an ALLOW. A second `decide` meanwhile refuses, and
  so does one whose record was replaced between its opening and its lock. Run it again with
  fresh readings once the first has returned. `start` holds the same lock on the previous
  record while it reads the chain and writes the new record.
- **A leftover `NAME.json.new`.** `decide` writes the record to `NAME.json.new` and then renames
  it. A leftover file means a `decide` stopped in between and never returned its decision, so
  its ALLOW reached no one. Every later `start` and `decide` refuses and names the file. The
  operator inspects it, compares it with `NAME.json`, and removes it by hand. Then take fresh
  readings and run `decide` again.
- **Signed tags.** `--manifests` is a local clone of GrapheneOS's `platform_manifest` with its
  tags. Every release tag in the range must verify with `git verify-tag` against the allowed
  signers file that `upstream/bases` pins. The command line pins `gpg.ssh.program` to
  `/usr/bin/ssh-keygen`, `gpg.program`, `gpg.openpgp.program` and `gpg.x509.program` to
  `/usr/bin/false`, `gpg.minTrustLevel` to `fully` and `gpg.ssh.revocationFile` to `/dev/null`,
  so the clone's own config cannot change the result and only SSH signatures verify. Every tag
  in the range needs a base record and an adevtool record. Each record must name the adevtool
  commit that its tag's signed manifest pins, and the tree commit it was derived from.
- **The approval** names its session and date:

  ```json
  {"schema": "andrix.pixel.approval/2", "session": "S2", "date": "2026-10-10",
   "artifacts": [{"sha256": "<64 hex>", "kind": "grapheneos", "wipes_data": true}]}
  ```

  An image that meets the criterion but is not named gives WAIT. Nothing is written in stage 3,
  and no Andrix image before stage 8.
- **Other inputs.**
  - `--update-pending` is `yes`, `no` or `unknown`, and unknown counts as pending.
  - `--channel` must be `stable`.
  - `--stable` is the content of `releases.grapheneos.org/caiman-stable`, and
    `--stable-fetched-at` is the time it was read.
  - The patch level for the rollback index comes from `upstream/bases/TAG.json` where that
    exists.
- **Disk space.** Rebuilding the dynamic partitions from the super splits needs several GB
  under `TMPDIR`: the splits, the merged super image and the unpacked partitions, about three
  times the size of super.

## A session, step by step

The operator's steps, in order. Nothing here replaces the plan's stop points, it only places
the checkers among them.

1. **Before the session.** The owner's approval names the session, its date and every artifact
   by SHA-256, as above. The date is the UTC date on which the session starts.
2. **Stop point 1, in the OS.** No update is downloading, installing or waiting for a reboot. If
   one is, wait for it, reboot into it and start again. Record the build number shown in
   Settings, the release channel, which must be Stable, and whether security previews are
   enabled. If the OS does not boot, stop point 1 is skipped as the plan's exception says, and
   `decide` gets `--os-booted no`.
3. **`start`.** The very first session gives `--first-release`. Every later session gives
   `--previous` with the newest record of the session directory and `--previous-sha256` with the
   SHA-256 the owner kept. If the build number of step 2 is newer than every release the newest
   record knows, the phone updated itself. Then save caiman-stable with `curl -o` and run
   `start` within 15 minutes with `--updated-from-stable` and `--build-number`. If `start` says
   the session waits, the phone has not reached the stable release yet: let it update, and go
   back to step 2.
4. **Stop point 2, in fastboot mode.** On the bootloader screen that shows "Fastboot Mode", run
   `readings.sh` with the sealed fastboot into a new readings file.
5. **Stop point 3.** Run `readings.py` with the session's stage. `decide` checks it again.
6. **`decide`**, at most 15 minutes after the readings. ALLOW: run the named image's complete
   script and nothing else. WAIT: stay in fastboot mode until a fresh approval names the image,
   then go back to step 4. REFUSE: write nothing, and read the reasons.
7. **Before every further write**, repeat steps 4 to 6 with fresh readings. A partial write is
   run again the same way.
8. **After the last `decide`**, the owner takes the SHA-256 of the session record, for example
   with `sha256sum sessions/S2.json`, and keeps it privately for the next session's
   `--previous-sha256`. Nobody edits the record afterwards.

## Where adevtool records each tag's stock build

adevtool records the stock build of a tag as `device.build_id` in the device config.
`config/device/caiman.yml` includes `common/gen9pixel.yml`, which includes `common/pixel.yml`.
That file includes fifteen section files, none of which sets `device`.
`src/config/config-loader.ts` pushes every include before the file that includes it
(`loadOverlaysRecursive`, `overlays.push(root)`) and merges in that order
(`loadAndMergeConfig`), so the last value wins. adevtool downloads and extracts exactly that
build: `src/commands/download.ts` line 53 and `src/build/make.ts` (line 164 at 2026081300, 166
at 2026100600).

| Tag | Stock build | Set at | Bootloader and baseband in the generated `android-info.txt` |
|---|---|---|---|
| 2026081300 | CP2A.260805.005 | `config/device/common/pixel.yml` line 24 | `ripcurrentpro-17.0-15199480`, `g5400c-260317-260429-B-15308590` |
| 2026100600 | CP3A.261005.005 | `config/device/common/gen9pixel.yml` line 6 | `ripcurrentpro-17.0-15819938`, `g5400c-260604-260807-B-16035863` |

`config/build-index/build-index-main.yml` lists each stock build with its factory image
SHA-256, carrier variants included, for example `caiman CP2A.260805.005.A1`, "Aug 2026,
Rogers". It does not say which build a tag uses. The generated module under
`vendor-skels/google_devices/caiman` records the same build ID twice, in the `BUILD_ID` check of
`caiman.mk` and in `cmds-for-envsetup.sh`. Its `firmware/android-info.txt` comes from
`generateAndroidInfo` in `src/images/firmware.ts`, from the stock vendor build properties.
`adevtool_record.py` reads all of these strictly and refuses when they disagree. It also refuses
a config that sets `backport_build_id`, `prev_build_id` or a firmware backport flag, because then
firmware could come from a second stock build.

## The flash script forms

GrapheneOS writes `flash-all.sh` in two forms, and the reader supports both.

- **Legacy.** `device/common/generate-factory-images-common.sh`, identical in both trees, as
  `script/generate-release.sh` sources it for caiman. That sets `DISABLE_UART`, `DISABLE_FIPS`,
  `DISABLE_DPM` and `AVB_PKMD`, and takes the bootloader and radio names from
  `android-info.txt`, lowercased. The whole text is then fixed by the two versions and the build
  number, so the script must equal it byte for byte.
- **Optimized.** `fastboot -S 0xf900000 optimize-factory-image` writes the published install
  zip. `FlashCapturer::Run` and `parse_flash_all_sh` in `system/core/fastboot/fastboot.cpp`
  (identical in both trees) keep the legacy prolog, add `check-var` blocks for `product` and
  `slot-count`, and copy the bootloader sequence. After the second bootloader reboot they add a
  `max-download-size` check, `fastboot --set-active=a` and a `current-slot` check. Then come the
  radio, `avb_custom_key`, UART, FIPS and DPM lines, the requirement check through
  `android-info.zip`, and `fastboot snapshot-update cancel` from `CancelSnapshotIfNeeded`. All of
  that must equal the expected text byte for byte. The OS images follow from the image zip's
  `fastboot-info.txt`: the static images as `fastboot flash P P.img`, the wipe erases, and a
  numbered run of `fastboot flash super super_N.img`.

The static image list, its order and the wipe erases of the optimized form are unconfirmed.
The set is caiman's `AB_OTA_PARTITIONS` in adevtool's generated `BoardConfig.mk` without the
firmware and the dynamic partitions. The order is that of AOSP's generated `fastboot-info.txt`
as recalled, because adevtool sets no `TARGET_BOARD_FASTBOOT_INFO_FILE` and AOSP's build files
were not available. A real script that differs is refused. `--os-images` and
`--wipe-partitions` take a reviewed list once a real install zip has shown it. `flash-all.bat`
and `script.txt` are not read.

Outside the official lines, the reader also names each forbidden command: lock and unlock
commands, `set_active`, `--set-active`, `--slot`, `--force` and their getopt abbreviations,
other flashes, erases and formats, verity switches, other updates, and commands run through
`eval`, `sh -c`, variables or backquotes.

## Rules, code and failing controls

Each rule has at least one mutated input that the checker must refuse. The tests are in
`tests/`.

| Plan rule | Code | Failing controls |
|---|---|---|
| Stop point 1, no update pending, Stable channel | `version_criterion.decide` | `StopPointTests` |
| Stop point 2, fixed readings with the sealed fastboot | `readings.sh`, `readings.parse` | `ScriptTests` (logging stand-ins for fastboot and timeout: path, version, device selection, timeout); `ParserTests.test_refused_records` |
| Stop point 3, continue rules; rule 1 from stage 7 and `unlocked` from stage 8 | `readings.stop_point_3` | `StopPointThreeTests.test_stops` |
| Stop point 4, every firmware reading matches a known release | `check_firmware` | `test_partial_write_can_be_rerun`, `test_firmware_newer_than_every_known_release_refuses_every_write` |
| Stop point 4, newer by release number, or the same stock build | `criterion` | `test_older_release_with_another_stock_build_is_refused`, `test_same_stock_build_reruns` |
| The image's identity is read from the image | `grapheneos_image`, `andrix_image`, `stock_image` | `test_typed_session_facts_are_not_options`, `test_grapheneos_identity_for_the_criterion`, `test_andrix_identity_is_cross_checked`, `test_andrix_zip_with_other_firmware_is_refused`, `test_stock_image_is_identified_by_its_digest` |
| The session record and fresh readings | `start_session`, `decide` | `SessionTests`, `test_stale_readings_are_refused`, `test_session_flow` |
| Stop point 4, a phone that updated itself starts from the current stable release, newer than every carried release and shown by the build number | `start_session`, `stable_start`, `check_stable_entry` | `UpdatedFromStableTests`, `test_updated_from_stable_on_the_command_line`, `test_the_typed_updated_release_is_not_an_option` |
| One chain of session records, started only from the newest, whose SHA-256 the owner keeps | `read_chain`, `newest_link`, `start` | `ChainTests`, `test_decide_needs_the_newest_record` |
| One decide at a time, and a leftover `.new` refused until removed by hand | `lock_session`, `write_session`, `read_chain` | `test_a_held_lock_refuses_a_second_decide`, `test_a_record_replaced_while_locking_is_refused`, `test_a_leftover_new_file_is_refused_until_removed_by_hand` |
| Fresh readings before each write, at most 15 minutes old | `decide` | `test_readings_older_than_the_maximum_age_are_refused`, `test_readings_max_age_option` |
| The session date is the UTC date of its start, and the approval names it | `check_session`, `decide` | `test_session_date_is_the_utc_date_of_its_start`, `test_approval_names_the_session_kind_and_wipe` |
| Signed tags and records bound to their signed manifests | `signed_tags`, `bind_record`, `load_table`, `check_coverage` | `SignedTagTests`, `TableTests.test_refused_tables`, `BindingTests`, `test_records_cover_every_signed_tag_between` |
| Signature programs pinned against the clone's own config | `VERIFY_PINS`, `signed_tags` | `test_clone_config_cannot_change_the_verification`: SSH, OpenPGP and X.509 stand-ins that accept every signature |
| Release numbers end in 00 or 01 | `caiman.parse_release` | unknown suffixes refused; `test_security_preview_counts_as_its_base_release` |
| Stock build IDs compared only for equality | `criterion` | `test_stock_build_ids_are_never_ordered` |
| A stock image no release is built from is refused | `stock_image` | the real Rogers and September entries of adevtool's index |
| The approval names its session, date and the image with its wipe effect; stage 3 and Andrix before stage 8 | `load_approval`, `decide` | `ApprovalTests` |
| Exception: the newer of the recorded release and any image written in the session | `decide` | `test_reference_is_the_newer_of_recorded_and_written` |
| Exception: while an update is pending or unknown, only the current stable release | `decide` | `test_pending_update_allows_only_the_current_stable_release`, `test_snapshot_status_restricts_like_a_pending_update` |
| Gate step 8 at the desk | `desk` | `DeskTests` |
| Rule 2, never lock | `flash_script` | every lock command in both forms |
| Rule 3, firmware only from the official release | `flash_script`, `install_zip` | older firmware names; `android-info.txt` controls |
| Rule 4, only complete official scripts; no `set_active`, `--slot`, `--set-active`, `--force` | `flash_script` | `FORBIDDEN`; every deleted line |
| Rule 5, caiman, fastboot 35.0.1, official order | `flash_script` | product and version changes; every swap and every move of a command line |
| Rule 6, write only what the official script writes, always wiping | `flash_script` | other flashes, erases and formats; scripts without the wipe |
| Checks that need no phone, with the super splits rebuilt | `install_zip` | one control for each check in `ChecksWithoutVbmetaTests` and `FullKitTests` |

The OS image list of the optimized form, its order and the wipe erases are fixed in
`flash_script.py` and refuse any other script. They are unconfirmed until a real install zip
is read, and only a reviewed change to that file can change them.

## Limits

- **Unconfirmed answer forms.** The forms that `readings.py` accepts come from fastboot's source
  at 2026100600, not from a phone. The sealed platform tools may print differently. Every sample
  in the tests is synthetic. A session on the phone must confirm the forms before the parser is
  trusted. Until then any difference is refused.
- **Not built or generated yet.** `simg2img`, `lpunpack` and the workshop key are not built or
  generated yet, so their SHA-256 constants in `install_zip.py` are empty.
  - A real install zip is refused, because its dynamic partitions live only in the super
    splits.
  - Every Andrix zip is refused, until both the tools and the key are recorded.
  - The tests use stand-ins. The tool command lines follow the tools' usage texts and were not
    run with the real tools.
- **The base tag property.** Andrix's release signing does not add `com.andrix.build.base_tag`
  yet (design item 6).
- **The fetch time of caiman-stable** is the saved file's modification time, which `curl -o`
  sets to the time of the download. A tool that sets the server's time instead, as `wget` does by
  default, makes the file look stale, and `start` refuses it. `touch` can change the time, so the
  file must not be edited or touched by hand.
- **The build number** is typed from Settings. A wrong one can only refuse or raise the
  reference, because it must name the stable release or its security preview.
- **The lock** is an advisory `flock`. It binds `decide` and `start` and nothing else, so it does
  not stop an edit by hand. Keep the session directory on a local file system.
- **The rollback index** is checked against the patch timestamp, as the plan says. Where the build
  sets it was not read, because AOSP's build files were outside the sources available.
- **The committed records** carry the commits of the sealed carry report, which a test checks.
  The trees' Git metadata was outside this environment, so they have no `tree_head`, and
  `load_table` refuses them for a session until `adevtool_record.py record --tree` derives them
  again on the operator's tree. The tests bind copies of them to a synthetic signed manifest
  repository.

## Tests

```sh
python3 -B -m unittest discover -s scripts/pixel/tests -p 'test_*.py'
sh -n scripts/pixel/readings.sh
```

The tests need `bash`, `sh`, `ssh-keygen` and `openssl`. Cases that need local GrapheneOS trees
are skipped unless `ANDRIX_PIXEL_TREES` names them, for example
`ANDRIX_PIXEL_TREES=2026081300=/path/a:2026100600=/path/b`. Those cases derive the records again
from the real trees and compare the fixture copies with the trees. The vbmeta cases need the
pinned tree's avbtool, through `ANDRIX_PIXEL_TREES` or `ANDRIX_GRAPHENEOS_ROOT`.
`tests/fixtures/README.md` lists where each fixture comes from.
