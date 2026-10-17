# Upstream records

Public facts about the GrapheneOS releases Andrix builds on and how far its base lags them.
[`scripts/proof/grapheneos_carry.py`](../scripts/proof/grapheneos_carry.py) writes and checks
them. Its [documentation](../scripts/proof/grapheneos_carry.md) describes the method and limits.
`selected-base.json` selects the base the tools build on. Nothing else here selects a base, and
nothing here authorizes a build. The exact patch profiles in `patches/` remain the gate for that.

- `selected-base.json` names the base the tools build on: one release, its record in `bases/` and
  the SHA-256 of that record's bytes. It selects 2026081300.
  [`scripts/proof/grapheneos_base.py`](../scripts/proof/grapheneos_base.py) reads it and refuses a
  missing, changed or ambiguous selection and a record whose digest or form disagrees. The source
  verifier and the patch tools take the base's identity from it: the release tag, the manifest
  identity, the AOSP default revision, the project count, the HEAD revisions of the patched
  projects and the patch directory `patches/grapheneos-<release>/`. Switching the base is a
  reviewed change of this record, after a patch directory for the new base exists, with its own
  payload sync host record in `tests/installer-durability/`. Both can sit beside the selected
  base's before the switch: the production format guard reads only the selected base's patch
  directory, the payload sync tool only its record, and
  [`grapheneos_candidate.py`](../scripts/proof/grapheneos_candidate.md) checks a candidate in a
  scratch checkout whose own selection names it.
  [`grapheneos_export.py`](../scripts/proof/grapheneos_export.md) writes both from a sealed
  `CARRIED` report, with the carry tool's own functions.
- `bases/<tag>.json` holds one base record per release tag, derived from the signed manifest
  tag. It has the tag object and manifest commit, the manifest digest and the allowed signers
  digest. It also has the AOSP default revision, the project table digest and count, and the
  security patch level of the lunch release Andrix uses. It ends with the kernel prebuilt
  revisions and the revisions of the projects Andrix patches. `record --verify` derives it
  again.
- `ledger/frameworks-base.json` lists frameworks/base security fixes keyed by Change-Id. Each
  fix has its present, absent, backported or unresolved status in every base record, with the
  method that decided it and the result of the content check. The ledger also holds the
  GrapheneOS preview CVE lists for each base. Preview fixes are not public source.
- `reports/<base>-<target>.json` is a sealed carry report. The seal is the SHA-256 of the
  canonical JSON of every other field. A sealed report is never rewritten. A correction is a
  new report. Its `status` field is the one line divergence status.
- `surface.json` declares the dependency surface the check compares besides patch targets.
- `backports.json` lists Andrix patches that carry an upstream fix onto a base. There are none.

Current status, from `reports/2026081300-2026100600.json`:

```sh
python3 -B scripts/proof/grapheneos_carry.py status upstream/reports/2026081300-2026100600.json
```
