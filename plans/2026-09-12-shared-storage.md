# Shared-host storage review

**Status:** read-only inventory completed; no deletion, migration or archive removal
is authorized or performed by this review. Andrix and Outset share the host.
Andrix has substantial accumulated runtime storage; Outset's reported bulk usage
is too small to explain the capacity problem. Other owners' inaccessible data is
not treated as empty or disposable.

## Filesystem and project observations

The shared bulk filesystem is XFS, approximately 1.86 TiB, with about 25.7 GiB available
and 99% usage. Root is a separate ext4 filesystem with about 619 GiB available. Inode
usage is only 14% on bulk: this is a capacity problem, not inode exhaustion.

The owner forwarded Outset's
[storage review](https://github.com/nicholasraimbault/outset/blob/master/builders/worldwide/STORAGE-REVIEW.md),
measured September 12 at 18:39–18:40 UTC. It reports 2.43 GiB in Outset's bulk directory;
most of its visible data is on root. Those figures are attributed to that agent,
not an Andrix inspection of Outset's private files. Cleaning Outset's working
caches would not materially solve bulk capacity and is not proposed here.

Andrix's read-only walk completed at 18:36:53 UTC; follow-up runtime/extent metadata
was inspected around 19:39–19:46 UTC:

| Andrix area | `du` allocated GiB |
| --- | ---: |
| Runtime work directories (39) | 1,089.71 |
| Android source/build trees | 619.78 |
| Evidence collections | 331.43 |
| Preserved Vanadium experiment | 75.85 |
| Native toolchain build directories | 5.32 |
| Temporary work | 1.04 |

**These are not exclusive physical usage or deletion-recovery estimates.** XFS
reflink-shared extents are counted in more than one directory's allocation. The
Andrix walk totals 2,123.14 GiB—larger than the filesystem precisely because its counts
include sharing. Sparse files and hard links also require care. A frozen boot-image
sample has both holes and reflink-shared extents.

## Main runtime consumers

| Runtime file class | Files | Allocated GiB | Shared extents observed |
| --- | ---: | ---: | ---: |
| `qemu.mem` RAM backing | 37 | 148.00 | 0 GiB |
| `os_composite.img` combined disks | 39 | 636.86 | 146.97 GiB |
| `overlay.img` guest-write layers | 39 | 18.14 | Not yet assessed as a class |

All inspected RAM-backing and combined-disk files have one hard link. FIEMAP reported
no unknown/delayed-allocation extents in those two classes. This does not make the
combined disks disposable: guest-write overlays can depend on their exact contents.
Do not delete or truncate those disks, overlays, or components based on their names.

The pinned Cuttlefish QEMU manager explicitly uses `qemu.mem` as a preallocated,
shared file-backed RAM object. It is not a complete saved VM snapshot, and it is not
in the inspected assembler's disk-resume preservation list. No Andrix QEMU process
was seen running. No RAM-backing references were found in evidence `SHA256SUMS` files.
No open descriptors or memory mappings to the 37 files were found among inspectable
Andrix-owned processes. A few protected systemd/PAM/GPG/SSH processes could not be
fully inspected; this was not an administrator-wide `lsof` proof. Recheck liveness
and open references immediately before any approved cleanup.

## Proposed first recovery — approval required

Remove **only the 37 stopped-runtime `qemu.mem` RAM backing files**, after final
per-file stoppedness, reference and retention checks. Expected recovery is roughly
**148 GiB**, bringing bulk headroom from about 26 GiB to about 174 GiB if observations
remain unchanged. This is a proposal to discard transient guest RAM, not guest disks,
source, keys, overlays, logs, sealed evidence or accepted image artifacts.

No deletion has occurred. Keep an explicit candidate ledger and before/after capacity
measurements if this proposal is approved. Do not use recursive directory deletion,
truncate hard-linked files, clear another project's locks, or interfere with active
Outset previews/search/services.

## Longer-term options — not adopted yet

1. Validate lossless sparse storage for the large combined disk files, with identical
   logical contents/hash and preserved metadata. Measure first; do not assume all
   allocated space is zero-filled or safely reclaimable.
2. Evaluate verified archival of older complete runtime states onto root or additional
   storage, leaving a shared-root reserve. Copying reflinks to ext4 can expand their
   physical footprint; do not size a move from directory totals alone. Archiving frees
   bulk only after a verified copy and separately approved source removal.
3. Adopt an explicit retention policy for disposable RAM/generated runtime working
   files versus retained disks, evidence and reproducible inputs. Keep a working-space
   reserve for both projects before launching further large image trials.

The private inventory is selected by `out/storage-audit/EVIDENCE`. Metadata scans used
the shared heavy-work lease; Outset's active work and inaccessible directories were
not modified or treated as disposable.
