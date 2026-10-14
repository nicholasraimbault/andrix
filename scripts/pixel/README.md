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
| `neverallow_check.py` | Andrix's neverallow rules on the policy the phone would load (design item 2, steps A to G) |

## Use

```sh
P=scripts/pixel
# One record per tag, from a tree checked out at that tag. The tag manifest must hash to the
# digest upstream/bases/TAG.json pins, and vendor/adevtool's HEAD must be its revision.
python3 -B $P/adevtool_record.py record --tree "$TREE" --release 2026100600 --out 2026100600.json
python3 -B $P/adevtool_record.py verify --tree "$TREE" 2026100600.json

# caiman-stable, saved with curl -o into a fresh file right before it is used. The file's
# modification time is the fetch time. Never copy the file, and never use wget's timestamping.
rm -f stable/caiman-stable
curl --fail -o stable/caiman-stable https://releases.grapheneos.org/caiman-stable

# A session record, in the session directory, which holds only session records. The very first
# session starts from the current stable release, which the build number that stop point 1
# recorded from Settings must show.
python3 -B $P/version_criterion.py start --out sessions/S1.json --session S1 --date 2026-10-09 \
  --first --from-stable stable/caiman-stable --build-number 2026100600 > start.out
# Every later session starts from the newest record and the SHA-256 the owner kept of it. If the
# phone updated itself since, the current stable release starts the record in the same way.
python3 -B $P/version_criterion.py start --out sessions/S2.json --session S2 --date 2026-10-10 \
  --previous sessions/S1.json --previous-sha256 "$KEPT_SHA256" \
  --updated-from-stable stable/caiman-stable --build-number 2026100600 > start.out
# start, verify and decide print the record's new SHA-256 on their last line. The next verify
# or decide of the session needs it. A refusal prints none, and the record stays as it was, unless
# the new record had already taken its place; then the refusal prints its SHA-256 too.
keep_sha256() { tail -n 1 "$1" | grep -x '[0-9a-f]\{64\}' || printf '%s\n' "$RECORD_SHA256"; }
RECORD_SHA256=$(keep_sha256 start.out)

# Verify each kit or zip the session may write, once, before the readings. The slow checks run
# here, and the session record keeps the verified identity under the file's SHA-256.
python3 -B $P/version_criterion.py verify --record 2026081300.json --record 2026100600.json \
  --manifests "$MANIFESTS" --allowed-signers allowed_signers \
  --image grapheneos --zip caiman-install-2026100600.zip --stable stable/caiman-stable \
  --avbtool "$PINNED_TREE/external/avb/avbtool.py" --simg2img "$TOOLS/simg2img" \
  --lpunpack "$TOOLS/lpunpack" --session sessions/S2.json --record-sha256 "$RECORD_SHA256" > verify.out
RECORD_SHA256=$(keep_sha256 verify.out)

# In fastboot mode, the fixed readings with the sealed fastboot, then stop point 3.
sh $P/readings.sh "$SEALED/platform-tools/fastboot" > readings.txt
python3 -B $P/readings.py readings.txt --stage 8 --os-booted yes

# May this image be written now? Exit 0 ALLOW, 1 REFUSE, 3 WAIT for a fresh approval. decide
# hashes the zip again and takes the identity that verify kept.
python3 -B $P/version_criterion.py decide --record 2026081300.json --record 2026100600.json \
  --manifests "$MANIFESTS" --allowed-signers allowed_signers \
  --image grapheneos --zip caiman-install-2026100600.zip --session sessions/S2.json \
  --record-sha256 "$RECORD_SHA256" --readings readings.txt --stage 8 --os-booted yes \
  --update-pending no --channel stable --security-previews no --approval approval.json > decide.out
RECORD_SHA256=$(keep_sha256 decide.out)

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
  the factory digest that adevtool's index records. `verify` runs these checks once in the
  session and keeps the identity in the session record under the file's SHA-256. `decide`
  hashes the file again and takes that identity, which must still agree with the adevtool
  records it is given. A file that changed since, or was never verified, is refused. So the
  15 minutes of the readings cover only `decide`'s fast part. The decision names the file's
  SHA-256.
- **One read of a kit's bytes.** `install_zip.py` reads a GrapheneOS install zip, and an Andrix
  zip alike, once from its start to its end into a private copy: a new file that only the user can
  read and write, in a new directory that only the user can enter. That directory is made in the
  scratch directory that a caller such as the neverallow gate gives, or else in the system's
  temporary directory (`TMPDIR`), which needs room for one more zip. The SHA-256 it reports is
  that of the bytes copied, hashed as they were copied. The bytes that `ssh-keygen` verifies,
  every check of the archive and the SHA-256 of the bootloader and radio images all come from that
  copy, so each concerns exactly the bytes that the SHA-256 names. A zip changed or replaced after
  it was copied changes nothing that is checked or reported. A zip changed while it was copied is
  checked as the bytes that were read, and the SHA-256 names them. A path that is not a regular
  file, such as a FIFO or a device, is refused without waiting for it. The signature and the
  allowed signers file are read once each. `ssh-keygen` verifies private copies of exactly those
  bytes, and the allowed signers digest is checked on the same bytes. Every private copy is
  removed before the check returns, also when it refuses or fails. `PrivateDirectory` in
  `install_zip.py` makes each private directory under a random name of 128 bits. Anything that
  exists at that path already is refused and left as it is, before the path is the check's to
  remove. After an interruption the directory is removed too: by its cleanup, or where no
  handler can run, as entering the directory ends or while it is removed, by a backstop, a
  `weakref.finalize`, when its `PrivateDirectory` object is dropped or at the interpreter's
  exit. From the moment the path is the check's until a removal of it succeeded, it is in a
  registry of owned directories, and one exit sweep, which `install_zip.py` registers with
  `atexit`, removes at the interpreter's exit every directory still there. So a second
  interruption that stops a backstop at its very first instruction, where no handler can take
  it, leaves its directory to the sweep, also when it comes at the exit and stops the other
  backstops there. Each directory has its own handler in the sweep, so an interruption or a
  failure on one goes on to the next. A copy that cannot be removed is a refusal, or else a
  warning of the backstop or of the exit sweep, within the limits that the next item states.
  Only a passing report names the firmware digests. The manifest's signed tags are verified the
  same way, against a private copy of the allowed signers bytes that were read once and checked.
- **What can still leave a private copy.** A process ended without Python's cleanup leaves its
  private copies behind: one killed by SIGKILL, or by a signal that Python does not handle by
  default such as SIGTERM, or one that calls os._exit. So does an interruption at the very
  first instruction of the exit sweep itself, or of the new start that an earlier interruption
  gives it, which no Python handler can cover and only blocking SIGINT could close: the
  directories that the sweep did not reach stay, unnamed, unless a backstop that runs after it
  removes them. Every other directory that the cleanup cannot remove is named. A strict
  removal, at the end of a with block or after a failed entry, refuses, and its refusal names
  the directory. The backstop and the exit sweep cannot refuse: a directory that they cannot
  remove, also when an interruption stops its removal, stays, and a warning on stderr names it.
  At the exit, the sweep tries each directory that stays, and writes once more a warning that
  stderr did not take, as when an interruption stopped it; only a stderr that is closed or
  fails, or a second interruption of the same warning, loses the warning. One case remains
  theoretical: another process that makes a directory of the same random name after
  PrivateDirectory found the path free. If an interruption came before the path was given up,
  after that check but before mkdir made the directory, or after a removal ended but before the
  path left the registry of owned directories, while the backstop and the exit sweep are still
  armed for it, the cleanup could remove that directory.
- **The zip's own identity, read again.** For a GrapheneOS kit or an Andrix zip, `decide` also
  reads the zip's own `android-info.txt` and `vbmeta.img` again. It reads the zip once into a
  private copy, as `install_zip.py` does, in the system's temporary directory (`TMPDIR`), which
  needs room for one more zip. It hashes the bytes as it copies them and looks that SHA-256 up
  in the session record. Both small reads come only from that copy, so they are the bytes whose
  SHA-256 names the kept identity, whatever happens to the file meanwhile. The copy is removed
  before the decision, and a copy that cannot be removed refuses. Google's image is identified
  by its SHA-256 alone, so `decide` only hashes it. A path that is not a regular file is refused
  without waiting, whatever the image. No signature is checked again. The release that the
  vbmeta names, as the build number of its fingerprints or as an Andrix zip's base tag property,
  the stock build of its fingerprints and the `android-info.txt` must equal the kept identity. So
  an identity edited in the record is refused even when the record's SHA-256 was computed again
  by hand.
- **An Andrix zip** must also meet four conditions:
  - Its vbmeta must verify against the workshop key whose SHA-256 `install_zip.py` records
    (`WORKSHOP_PKMD_SHA256`).
  - Its `android-info.txt` and fingerprint stock build must equal its base tag's record.
  - Its bootloader and radio images must be byte identical to the verified official kit of
    that tag, given with `--official-kit`. The kit's digests are the ones `install_zip.py`
    reports for the bytes that passed its checks, and the kit is not opened again.
  - The base tag is the signed vbmeta property `com.andrix.build.base_tag`. Andrix's release
    script must set it from the tag it verified, never by hand.
  - `install_zip.py` reads the zip once into a private copy, as it reads a kit, and checks only
    that copy, so the SHA-256 it reports is that of the bytes it checked, whatever happens to
    the zip meanwhile.
- **The session record.** `--session` is the checker's own session record. It holds the
  phone's release recorded at the session's start, the releases carried from the previous
  session, the identities that `verify` kept, and every ALLOWed release. An ALLOW is written
  into it before the decision returns, so before the write runs. Its date is the UTC date of
  its start, and the approval names that date.
- **The session chain.** A phone's session records live in one directory that holds nothing
  else, each as `NAME.json` in the form the checker writes. Each record names the SHA-256 of the
  record before it, and exactly one record, the first, names none. `start`, `verify` and
  `decide` verify the whole chain and refuse a broken link, a fork where two records name one
  parent, a second first record, a repeated session name, any other file, and a `--previous` or
  `--session` that is not the newest record. Nothing points at the newest record, so each
  `start`, `verify` and `decide` that does not refuse prints the record's new SHA-256 on its
  last line. The next `verify` or `decide` of the session needs it as `--record-sha256` and
  refuses a record that no longer hashes to it, so an edit between two commands is caught. A
  refusal prints no SHA-256 and leaves the record unchanged, with one exception below. After the
  last command of a session the owner keeps the last SHA-256 privately. The next `start` needs it
  as `--previous-sha256` and refuses a newest record that no longer hashes to it. The SHA-256 is
  only ever the one a command printed. A lost value, or one the record no longer matches, ends
  the session for inspection. It is never taken from the file, with `sha256sum` or otherwise,
  because a value read from the file would accept any edit of it.
- **A refusal after the new record took its place.** If finishing the write fails once the new
  record is in place, such as the fsync of the directory after the rename, the record already
  holds the new ALLOW, verified identity or session. The command still refuses, so nothing is
  written to the phone. It names the failure and prints the record's new SHA-256 on its last
  line, computed from the bytes it wrote. The operator inspects the record and the disk, then
  keeps that SHA-256 and goes on with fresh readings. An ALLOW whose write never ran is the state
  that every ALLOW is in until its write runs, which the session record already accepts.
- **The first record** starts from the current stable release, never from a typed release:
  `start --first --from-stable FILE --build-number B`, with FILE and B as below. B must be the
  stable release or its security preview, or the session waits until the phone has updated.
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
- **One command at a time.** `verify` and `decide` hold an exclusive lock on the session record
  from before they read the record until after they write it. A second one meanwhile refuses,
  and so does one whose record was replaced between its opening and its lock. Run it again,
  with fresh readings for `decide`, once the first has returned. `start` holds the same lock on
  the previous record, and a lock on the session directory, while it reads the chain and
  writes the new record.
- **A leftover `NAME.json.new`.** `start`, `verify` and `decide` write a record to
  `NAME.json.new`, fsync it, and then rename it into place, and `start` never replaces an
  existing record. A leftover file means one of them stopped in between and never returned, so
  its result, an ALLOW among them, reached no one. Every later `start`, `verify` and `decide`
  refuses and names the file. The operator inspects it, compares it with `NAME.json`, and
  removes it by hand. Then take fresh readings and run the command again.
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
  - `--stable`, `--from-stable` and `--updated-from-stable` are
    `releases.grapheneos.org/caiman-stable`, saved with `curl -o` into a fresh file at that
    moment. Its modification time is the fetch time, so the file is never copied, and wget's
    default timestamping is never used. `start` and a `decide` that may meet a pending update
    refuse a file fetched more than 15 minutes before them or dated after them. `verify` and
    `desk` give `--stable` to the install zip checks, which compare the zip's release with it.
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
3. **`start`.** Where `start` needs caiman-stable, first remove the old file and save a fresh one
   with `curl --fail -o`, then run `start` within 15 minutes.
   - The very first session gives `--first --from-stable FILE --build-number B`, with B from
     step 2.
   - Every later session gives `--previous` with the newest record of the session directory and
     `--previous-sha256` with the SHA-256 the owner kept. If the build number of step 2 is newer
     than every release the newest record knows, the phone updated itself, and `start` also
     gives `--updated-from-stable FILE --build-number B`.
   - If `start` says the session waits, the phone has not reached the stable release yet. Let it
     update, and go back to step 2.

   Keep the SHA-256 on the last line of the output for the next command.
4. **`verify`** each kit or zip the session may write, once, at the desk, with the last
   SHA-256 as `--record-sha256`. The slow checks, super rebuilds included, run here. Keep the
   new SHA-256 it prints.
5. **Stop point 2, in fastboot mode.** On the bootloader screen that shows "Fastboot Mode", run
   `readings.sh` with the sealed fastboot into a new readings file.
6. **Stop point 3.** Run `readings.py` with the session's stage. `decide` checks it again.
7. **`decide`**, at most 15 minutes after the readings, with the last SHA-256 as
   `--record-sha256`. When the OS does not boot and an update may be pending, save a fresh
   caiman-stable with `curl --fail -o` and give it as `--stable`. Keep the SHA-256 that `decide`
   prints. A refusal prints one only after the new record took its place, as above, and then
   the record is inspected first. ALLOW: run the named image's complete script and nothing else.
   WAIT: stay in fastboot mode until a fresh approval names the image, then go back to step 5.
   REFUSE: write nothing, and read the reasons.
8. **Before every further write**, repeat steps 5 to 7 with fresh readings. A partial write is
   run again the same way. A kit or zip the approval adds later is verified first, as in step
   4.
9. **After the last command**, the owner keeps the last SHA-256 it printed privately for the
   next session's `--previous-sha256`. If it is lost, or the record no longer matches it, the
   session ends for inspection, and the value is never taken from the file. Nobody edits the
   record afterwards.

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
| The first record starts from the current stable release, never from a typed release | `start_session`, `stable_start`, `check_stable_entry` | `test_the_first_record_starts_from_the_stable_release`, `test_the_typed_first_release_is_not_an_option`, `test_stable_entry_controls` |
| Each start, verify and decide prints the record's SHA-256, and the next verify or decide needs it | `locked_record`, `report` | `test_each_decide_needs_the_sha256_the_last_command_printed`, `test_an_identity_edited_in_the_record_is_caught_by_the_chain` |
| Kits and zips verified once, decide takes the kept identity by SHA-256 | `verify`, `verified_image`, `check_identity`, `check_verified` | `VerifiedIdentityTests`, `test_decide_takes_the_identity_that_verify_kept`, `test_a_file_that_changed_since_verify_is_refused`, `test_an_identity_not_in_the_record_is_refused` |
| decide reads a kit's or zip's own release, stock build and `android-info.txt` again and refuses a mismatch with the kept identity | `own_identity`, `check_own_identity` | `test_decide_reads_the_zips_own_identity_again`, `test_an_identity_edited_with_the_sha256_computed_again_by_hand_is_refused` |
| A pending update decision reads caiman-stable's fetch time from the file | `check_fetch`, `read_stable`, `decide` | `test_a_stale_or_future_fetch_time_is_refused`, `test_pending_update_takes_the_fetch_time_from_the_stable_file` |
| start writes atomically and never over a record | `publish_record`, `lock_directory` | `test_start_writes_atomically` |
| One command at a time, and a leftover `.new` refused until removed by hand | `lock_session`, `write_session`, `read_chain` | `test_a_held_lock_refuses_a_second_decide`, `test_a_record_replaced_while_locking_is_refused`, `test_a_leftover_new_file_is_refused_until_removed_by_hand` |
| A refusal after the new record took its place prints its SHA-256 | `RecordWritten`, `write_session`, `publish_record`, `main` | `test_a_refusal_after_the_record_took_its_place_prints_its_sha256` |
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
| Every check reads one private copy of a kit's or zip's bytes | `install_zip` | listed below |
| No private copy is left unnoticed; a FIFO is refused at once | `install_zip` | listed below |

The OS image list of the optimized form, its order and the wipe erases are fixed in
`flash_script.py` and refuse any other script. They are unconfirmed until a real install zip
is read, and only a reviewed change to that file can change them.

The last two rows of the table, in detail. Their controls are in `test_install_zip.py` unless
`test_version_criterion.py` is named.

- `ZipCopy` reads a kit or zip once into a private copy and hashes the bytes as it copies them.
  `check`, `check_signature` and `andrix_identity` read only that copy, and so do
  `version_criterion.grapheneos_kit` for the official kit's firmware and
  `version_criterion.verified_image` for the identity that `decide` reads again. Controls:
  `test_a_zip_changed_after_it_was_copied_changes_nothing`,
  `test_a_zip_changed_while_it_is_copied_is_checked_as_read`,
  `test_a_kit_changed_after_it_was_copied_passes_as_copied`,
  `test_a_kit_changed_while_it_is_copied_is_checked_as_read`,
  `test_a_rewrite_put_back_within_one_timestamp_tick_changes_nothing`,
  `test_the_andrix_zip_is_read_once_into_a_private_copy`,
  `test_the_signature_and_the_allowed_signers_are_read_once`,
  `test_the_zip_is_read_once_from_its_start_to_its_end`,
  `test_each_small_input_is_read_in_one_read`,
  `test_ssh_keygen_verifies_private_copies_of_the_bytes_read`,
  `test_the_official_kit_is_not_opened_again_after_its_check`, and in
  `test_version_criterion.py` `OfficialKitTests`,
  `test_decide_reads_the_zips_own_identity_only_from_its_copy` and
  `test_a_stock_image_is_hashed_to_its_end`.
- `open_regular` refuses a path that is not a regular file without waiting, by what it opened,
  whatever the path names afterwards. `write_private` creates each private copy exclusively, and
  `remove_private` removes it or refuses, whatever error the removal meets. `PrivateDirectory`
  names each private directory by 128 random bits, made absolute, refuses a path where anything
  exists before the path is its own, then makes the directory, and removes it on every exit, an
  interruption too. Its backstop removes it where no handler can, and warns of what it cannot
  remove. The exit sweep removes, at the interpreter's exit, every directory still owned, also
  when a second interruption stopped its backstop, and names what it cannot remove; a warning
  that stderr cannot take raises nothing. A forked child owns none of its parent's directories.
  `ZipCopy` copies the zip inside it, from a link to a regular file too, whatever its size.
  Every caller of `ZipCopy`, `check_signature`, `check_vbmeta`, `rebuild_dynamic` and
  `version_criterion.signed_tags` enter theirs in their `with` statement. Controls:
  `test_the_private_copies_are_private_and_removed`,
  `test_a_copy_that_fails_once_its_directory_exists_leaves_nothing`,
  `test_an_interruption_at_any_boundary_of_the_copy_leaves_nothing`,
  `test_an_interruption_that_no_handler_covers_leaves_nothing_once_it_went_on`,
  `test_an_interruption_that_no_handler_covers_leaves_no_extracted_image`,
  `test_an_interrupted_copy_that_cannot_be_removed_refuses`,
  `test_a_private_directory_whose_path_exists_is_refused_and_left_alone`,
  `test_a_path_that_exists_is_left_alone_wherever_an_interruption_comes`,
  `test_a_path_that_another_makes_after_the_check_is_refused_and_left_alone`,
  `test_the_private_directories_of_vbmeta_are_owned`,
  `test_a_failed_copy_that_cannot_be_removed_refuses`,
  `test_a_private_copy_that_cannot_be_removed_refuses`,
  `test_a_path_that_is_not_a_regular_file_is_refused_without_waiting` in both files,
  `test_a_device_replaced_by_a_regular_file_once_opened_is_refused`,
  `test_every_private_copy_goes_when_a_check_raises`,
  `test_a_zip_copy_that_cannot_be_removed_discards_the_kept_images`,
  `test_extracted_images_that_cannot_be_removed_refuse_vbmeta`,
  `test_an_io_error_that_keeps_the_copy_is_printed_as_a_refusal`,
  `test_a_backstop_stopped_at_its_entry_leaves_its_directory_to_the_exit_sweep`,
  `test_a_backstop_stopped_at_its_entry_leaves_no_extracted_image`,
  `test_python_removes_at_its_exit_what_a_stopped_backstop_left`,
  `test_python_removes_at_its_exit_the_extracted_images_that_a_stopped_backstop_left`,
  `test_a_link_to_a_regular_zip_is_read_as_the_zip`,
  `test_a_zip_with_a_member_larger_than_128_mib_is_checked_as_any_other`,
  `test_a_kit_with_a_member_larger_than_128_mib_passes`,
  `test_a_relative_scratch_directory_passes`, the tests of `PrivateDirectoryTests`, and in
  `test_version_criterion.py`
  `test_the_allowed_signers_copy_is_private_and_removed` and
  `test_the_copy_that_decide_reads_is_removed`.

## The neverallow check

adevtool sets `SELINUX_IGNORE_NEVERALLOWS := true` for caiman, so a caiman build checks none of
Andrix's 28 neverallow rules. `neverallow_check.py` checks them afterwards on the policy the
phone would load. It follows item 2 of the
[stage 1 design](../../plans/2026-10-09-caiman-design-items.md#2-the-neverallow-check).

```sh
# The gate, on the Andrix install zip to be flashed. Exit 0 PASS, 1 REFUSE.
python3 -B $P/neverallow_check.py --zip caiman-install-BUILD.zip \
  --official-kit caiman-install-2026100600.zip --release-record release.json \
  --expanded "$OUT/soong/.intermediates/system/sepolicy/sepolicy_neverallows.sepolicy_analyze.conf/android_common/sepolicy_neverallows.sepolicy_analyze.conf" \
  --variant user --grapheneos-tree "$TREE" --allowed-signers allowed_signers \
  --stable caiman-stable --record 2026100600.json --avbtool "$PINNED_TREE/external/avb/avbtool.py" \
  --simg2img "$TOOLS/simg2img" --lpunpack "$TOOLS/lpunpack" --debugfs "$TOOLS/debugfs" \
  --sepolicy-analyze "$TOOLS/sepolicy-analyze" --secilc "$TOOLS/secilc" --checkpolicy "$TOOLS/checkpolicy"
# Corpus mode, on a product that is not a caiman image: CORPUS (exit 3) or REFUSE (exit 1)
python3 -B $P/neverallow_check.py --corpus --partitions "$CORPUS" --base-tag 2026081300 \
  --expanded "$EXPANDED" --variant userdebug --grapheneos-tree "$TREE" \
  --sepolicy-analyze "$TOOLS/sepolicy-analyze" --secilc "$TOOLS/secilc" --checkpolicy "$TOOLS/checkpolicy"
# The release wrapper's check: the build's own host tools against the base tag's reviewed set
python3 -B $P/neverallow_check.py --build-tools "$OUT/host/linux-x86/bin" --base-tag 2026100600
```

**What the gate reads, and where it comes from.** No input that decides the gate is typed.

- `--zip` is the Andrix install zip. `install_zip.py` verifies it as for the version criterion:
  the workshop key, vbmeta, `avbtool verify_image` on every image vbmeta names, with the super
  splits rebuilt by the pinned `simg2img` and `lpunpack`. The base tag is its signed
  `com.andrix.build.base_tag` property. `install_zip.py` moves the images it verified into an
  empty directory and empties it again when its whole check does not pass. `debugfs`, pinned in
  `install_zip.py` beside `simg2img` and `lpunpack`, reads the policy files out of them: each
  partition's `etc/selinux`, the system image's `/system/build.prop`, and `/odm/etc/selinux`
  from an odm image or else from the vendor image's `/odm`, where `/odm/etc` leads on a phone
  without an odm partition.
  `debugfs` exits 0 even for a missing path, so any message besides its banner refuses.
- `--official-kit` is the official GrapheneOS install zip of the base tag. `install_zip.py`'s
  checks must pass it for that tag: signature, allowed signers, `avb_pkmd.bin`,
  `android-info.txt`, vbmeta, release identity and flash script, all on one private copy of the
  kit, whose SHA-256 the report names. Its policy is read out of its verified images the same
  way, and its hash pairs are checked as in step A.
- `--release-record` is the build's release record, schema `andrix.caiman.release/1`, which the
  release wrapper of design item 6 is to complete: `base_tag`, `artifacts.install_zip.sha256`
  and `artifacts.expanded_rule_file.sha256`. The zip and `--expanded` must hash to these, and the
  zip's signed base tag must be the record's. The expanded rule file is read once, and the steps
  check the text whose digest was compared. When the digests differ, no step reads it.
- The Andrix policy directories come from `board/owner-policy.mk`, which may hold only comments
  and `+=` additions under `vendor/andrix/`, and no directory under `tests/`. Lines are joined
  as make joins them. A comment that a final backslash continues, a backslash before a line's
  end and trailing white space refuse. The expanded rule file names each source file it was
  made from in an m4 line marker, and every `vendor/andrix/` file named there must lie in one
  of these directories, so a build that read Andrix policy from elsewhere refuses. The patch set
  is `patches/grapheneos-TAG` for the base tag. Each patch there needs its record, and each
  `system/sepolicy` record must name that tag. `--policy-dir`, `--patches` and `--file` are
  refused by name in every mode, and `--official` in the gate and in corpus mode, so a caller
  cannot give a list that leaves an Andrix rule out.
- `sepolicy-analyze`, `secilc` and `checkpolicy` must hash to the base tag's reviewed set in
  `TOOL_PINS`. A tag without a set refuses, because equal sources at two tags do not stand for
  equal compiled tools. Only the 2026081300 set exists, and it serves only the stage 1 corpus, as
  the design says: corpus mode uses it, and the gate refuses it for an image. `--build-tools` is
  the release wrapper's check that the build's own host tools hash to the set. The wrapper
  releases images, so it refuses the corpus set too.
- `--expanded` is the build's expanded rule file. The existing module always expands for `user`,
  so a `userdebug` build needs its own module with the real variant.
- `--variant` must equal `ro.build.type`. It selects rule 11's expansion, which keeps
  `-overlay_remounter` for `userdebug`.
- `--grapheneos-tree` is the GrapheneOS source tree of the base tag. Only the `system/sepolicy`
  file that each patch record names is read. It must hash to the record's `upstream_sha256`, or
  to its `adapted_sha256` and then give the upstream bytes with the patch taken back out. The
  patch applied to the upstream bytes must give the adapted ones.
- `neverallow_witnesses.json` holds each rule's source line, literal text, `user` and `userdebug`
  expansions and witness, one CIL `allow` of one permission inside the rule. Its `changes` list
  records each patch hunk that changes an existing rule, with its patch line, its lines, the
  rule's upstream line and its effect. The two narrowings of the bridge patch are recorded there.

**Corpus mode.** `--corpus` runs the check on a real policy that is not a caiman image, the Andrix
Cuttlefish product. Its only verdicts are CORPUS and REFUSE, it exits 3 or 1 and never 0, not even
for `--help`, so it can never pass the gate. It departs from the gate only where the corpus is not a
caiman image. It takes `--partitions`, a directory of the corpus's partition files laid out as on
the phone, and `--base-tag`, because a corpus image carries no signed base tag. A typed tag can only
choose a reviewed set of pins and a patch directory. Step A takes the precompiled policy init would
load, from odm before vendor, with its hash files beside it, and records a
`userdebug_plat_sepolicy.cil` instead of refusing it. Step C looks the `user` expansions up in the
expanded rule file, which the build makes for `user` only, and checks the variant's expansions
against the table. Step D runs the variant's rules, and on a `userdebug` corpus also the `user`
rules, which must fail with exactly `allow overlay_remounter andrix_owner_entry:file { execute };`.
Step F does not run, because no official release exists for the product, and `--official-kit` is
refused. Step G runs on the corpus files alone and must find no violated rule.

**Steps.** Every step runs and reports, and the policy passes only if all pass. In the gate the
provenance checks `release_record`, `image`, `expanded_rule_file` and `official_kit` come first.

| Step | Passes only if |
|---|---|
| A | `/vendor/etc/selinux/precompiled_sepolicy` exists, no other `precompiled_sepolicy` and no `userdebug_plat_sepolicy.cil` exists anywhere, `ro.build.type` is the variant, and each of the three hash pairs is one equal line that the CIL file followed by its mapping file hashes to |
| B | `sepolicy-analyze POLICY attribute domain` lists `andrixd`, `andrix_owner` and `andrix_terminal` |
| C | every `vendor/andrix/` file that the expanded rule file's line markers name lies in a directory of `board/owner-policy.mk`, every literal `neverallow` in the sources has exactly one entry, each entry's text is its line, its expansion is the rule with the three known macros applied, and that expansion is a statement of the expanded rule file. A literal `neverallowxperm` or an unknown macro refuses. Each run of changed lines in a patch hunk is placed in the upstream file and read with m4's lexical state there: quotes `` ` `` and `'`, and `#` comments, which m4 sees only outside quotes. Unchanged context lines are no change. A run that removes a `neverallow` or `neverallowxperm` line, changes text inside such a statement or inside an m4 macro definition, names an m4 builtin that defines macros or changes m4's input, is not balanced in itself, closes a quote or parenthesis opened before it, or adds an argument to a macro call open around it, needs an exact record in `changes`. So does an m4 builtin of that kind in a policy file. Blank lines and comments that m4 skips at the top level change nothing. Inside a quoted string a `#` starts no comment, so such text is judged like any other |
| D | `sepolicy-analyze POLICY neverallow -w -f RULES` on the 28 expansions exits 0 and prints nothing, so a warning fails like a violation |
| E | `secilc` with init's arguments and file order gives a control whose `checkpolicy -M -b -C` text equals the loaded policy's, the control passes, and each witness added as one more CIL file fails its own rule alone and the whole set, with exactly its own violation |
| F | the official policy's hash pairs hold as in step A, and every other `neverallow` of the expanded rule file gives no violation and no warning on this policy that the official policy does not give too. Shared violations are listed as vendor findings, and warnings on both are listed |
| G | `secilc` without `-N`, with the build's check flags, over this policy's CIL files reports no pair of a violated rule and one offending rule that the same run on the official files does not report. Places are dropped, and each generated attribute, `base_typeattr_N` or `base_typeattr_N_V`, is replaced by its `typeattributeset` expression from the same run's CIL files, recursively. The definitions are read from CIL tokens as secilc reads them: white space may stand between any two tokens, a quoted string is one token and never a definition, and a comment runs from `;` to the next newline token, so a carriage return inside a quoted string does not end it. A name without a definition, defined twice or through itself refuses, and so does a file secilc could not parse |

**Limits.**

- No real install zip is read yet. `debugfs`, `simg2img` and `lpunpack` are not pinned in
  `install_zip.py` and the workshop key is not recorded, so the gate refuses every real zip. The
  tests stand in for `install_zip.py`'s verification and read real ext4 images with the pinned
  tree's `debugfs`.
- Only the 2026081300 tools are pinned. A caiman build at 2026100600 needs that tag's compiled
  tools built and pinned in a reviewed change.
- The release record is read as the release wrapper of design item 6 is to write it. That
  wrapper does not exist yet.
- The gate reads the partitions' policy directories, not the boot images. A
  `userdebug_plat_sepolicy.cil` in a debug ramdisk is not seen. The flash script check keeps
  debug boot images off the phone.
- Step F compares warnings by their text, which names the undefined name but not the rule.
- Step G compares expressions as text, after the generated names are expanded. It cannot see a
  change in the members of a named attribute, such as Andrix domains in `domain`, because both
  runs print the same name. Steps D and F cover the Andrix rules and the AOSP rules for that.
- Step C places hunks by the text of the upstream file, not by m4's expansion of it. It sees a
  change inside a statement or a macro definition, and m4 builtins that redefine, but not a rule
  weakened through a macro that a hunk outside those places changes in another way. It follows
  m4's quotes and comments, and counts every parenthesis outside quotes, which is stricter than
  m4, which counts them only inside a macro call.
- The stage 1 corpus, the Andrix Cuttlefish product, cannot pass the gate, which reads only
  install zips. Corpus mode checks it without ever passing.

## Limits

- **Unconfirmed answer forms.** The forms that `readings.py` accepts come from fastboot's source
  at 2026100600, not from a phone. The sealed platform tools may print differently. Every sample
  in the tests is synthetic. A session on the phone must confirm the forms before the parser is
  trusted. Until then any difference is refused.
- **Not pinned or generated yet.** `simg2img`, `lpunpack` and `debugfs` are not reviewed and
  pinned, and the workshop key is not generated yet, so their SHA-256 constants in
  `install_zip.py` are empty. The three tools are to come from one reviewed host tool set.
  - A real install zip is refused, because its dynamic partitions live only in the super
    splits.
  - Every Andrix zip is refused, until both the tools and the key are recorded.
  - The tests use stand-ins. The tool command lines follow the tools' usage texts and were not
    run with the real tools.
- **The base tag property.** Andrix's release signing does not add `com.andrix.build.base_tag`
  yet (design item 6).
- **The fetch time of caiman-stable** is the saved file's modification time, which `curl -o`
  sets to the time of the download. A tool that sets the server's time instead, as `wget` does by
  default, makes the file look stale, and it is refused. A copy made with `cp` gets the time of
  the copy, which would make an old file look fresh, and `touch` can change the time. So the
  file is always saved fresh with `curl` and never copied, edited or touched by hand.
- **The build number** is typed from Settings. A wrong one can only refuse or raise the
  reference, because it must name the stable release or its security preview.
- **The lock** is an advisory `flock`. It binds `start`, `verify` and `decide` and nothing else,
  so it does not stop an edit by hand. The SHA-256 that each command prints catches such an
  edit at the next command. Keep the session directory on a local file system.
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
The neverallow cases of steps B and D to G need `sepolicy-analyze`, `secilc` and `checkpolicy`
from the pinned tree's host output, through `ANDRIX_PIXEL_TREES`. The cases that read ext4
images need `mke2fs` and `debugfs` from the same output.
`tests/fixtures/README.md` lists where each fixture comes from.
