# GrapheneOS 2026100600 candidate patches

These are Andrix's six patches, carried from the selected base, 2026081300, to GrapheneOS
2026100600. They are a candidate. `upstream/selected-base.json` still selects 2026081300, and no
production tool reads this directory until a reviewed change selects 2026100600.

## Provenance

`scripts/proof/grapheneos_export.py` wrote this directory from a sealed carry report:

- report: `upstream/reports/2026081300-2026100600.json`, verdict `CARRIED`
- seal: `6be89efc1117123edf3798991d4ff2aa3c966a13784aab46ed2fd5627b75f54d`
- `frameworks/base`: `84183aff99be5e156dc0446a6fa2d4a7150f4bc3`
- `system/sepolicy`: `5e359dcf9ae863a593e9055a85e1657c87c4cb18`

Every patch here is the 2026081300 patch byte for byte. Each was applied at fuzz 0 with the carry
tool's own functions to the pristine files of both releases, read as Git objects of a local source
tree authenticated against the signed 2026100600 manifest, and every result equals the sealed
report. The profiles name the revisions above and the actual upstream and candidate digests.

Of the 15 upstream files the patches change, 12 are identical at 2026100600.
These changed upstream, and the patches still apply at fuzz 0:

- `services/core/java/com/android/server/pm/InstallPackageHelper.java`: moved, at line offsets
- `services/core/java/com/android/server/StorageManagerService.java`: moved, at line offsets
- `services/core/java/com/android/server/pm/PackageManagerShellCommand.java`: changed clean

The payload sync companion's host tested record is this base's own:
`tests/installer-durability/grapheneos-2026100600/pis-reverse-write-sync.candidate.json`.
Its patch and source fragments are shared with 2026081300.

## Lab only

`native-identity-writer.*` is carried as checked lab test source only. A normal image does not
apply it, and its lab admission rules are unchanged.

## Owner policy bridge

`owner-session-policy.*` is the same digest guarded private bridge, recorded for the 2026100600
revision of `system/sepolicy` above. Its upstream `private/domain.te` is the file that
`scripts/proof/owner_policy.py` pins, byte for byte, and the zero context review patch reproduces
the bridge there. It adds no public policy API and changes no existing domain's grants.

## Qualification

Source only. The candidate's source gate is `scripts/proof/grapheneos_candidate.py check` in a
scratch checkout that selects 2026100600. No build, boot, runtime or security result follows from
this directory, and no Android result of 2026081300 carries over to it.
