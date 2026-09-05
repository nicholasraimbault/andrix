# Source and artifact provenance

Public history starts with the accepted direct-AOSP-17 integration baseline,
then records meaningful product, implementation, proof and documentation
changes. Machine setup, agent-tool switching, empty commits and lab-only index
churn are not the public development history. The complete original history
and the earlier publication are archived privately.

This is a curated snapshot history, not a verbatim operating journal. Selected
implementation snapshots retain their source contents and author dates, with
public-facing commit subjects. Setup and publication housekeeping are folded
into the baseline and final documentation/licensing snapshot. All commits use
the owner's verified GitHub-linked noreply identity.

## Frozen proof inputs

The [revision map](source-revision-map.tsv) links original pre-publication
build/proof revisions to corresponding public code snapshots. For these pins,
Android product/APEX/init/SELinux inputs and proof/test sources were compared
by path, file mode and Git blob ID. They are unchanged. Whole tree hashes can
differ because operator files and publication-only documentation are not build
inputs and are not preserved as public lab history.

| Work | Original revision |
| --- | --- |
| Initial source placement | `c2efc55451d25cf4ce3a241e17820e8700f9f546` |
| Signed proof APEX producer | `10abbcd754837aec47eb193058457365d84e3d51` |
| P2 checker / baseline complete image | `0a3282f77d98922aa8fe99233b26002e903633dd` |
| Optional P5 APK producer | `0dfe6b61220bbd3ab491cc60bbfb2392aab23138` |
| P5 artifact metadata checker | `6c17ac63c876471729e9b728c089e7dbf239edf9` |
| Partial network-control image producer | `200c03ef8be60f53292e158ed591109125f7bb9a` |

Original commit objects, signed artifacts and raw evidence were not rewritten.
Do not relabel an old artifact as a new build or infer a runtime result from a
source revision. The AOSP tag, pinned manifest and recorded artifact SHA-256
values remain unchanged.

The frozen artifact hashes predate the publication license and Soong license
metadata. Subsequent builds must recheck their artifacts rather than assuming
identical notice/container bytes. The current status and missing runtime gates
are in [plans/current.md](../plans/current.md).

Private signing keys, credentials, operator configuration and raw lab evidence
remain outside the public repository.
