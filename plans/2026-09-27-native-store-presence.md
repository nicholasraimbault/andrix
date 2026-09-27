# Native store presence is not a boolean

Status: source, independent review and guarded host controls, followed by actual Android
compilation in `cac0ba6`. The final normal image contains the presence reader. Inactive native
writer paths were removed by R8, so these host write controls are not Android writer runtime
qualification. Native execution and version 2 publication stay disabled.

## Correction

`Files.exists` and `Files.isDirectory` return false when attributes cannot be read. That is not the
same as an absent path. The former store could acknowledge a RELEASING directory as absent after
an access failure and then omit its header entry. Other holds prevented final UID reuse in the
examined path, but the lower level acknowledgement was false and left recovery work behind.

The store now distinguishes present, absent and unknown through a stat that does not follow the
final symbolic link. Only `NoSuchFileException`, mapped from ENOENT in the inspected Android
libcore, establishes absence. Access errors, ENOTDIR and other observation failures do not.
Every absence dependent writer step uses that distinction, including initialization, directory
creation, release confirmation, header omission and the final backup check.

Unreadable bytes are also different from malformed bytes. A readable version 1 record with a bad
checksum can retain its existing owned recovery behavior. A copy that cannot be read may instead
contain newer state. It blocks native store mutation rather than being overwritten through an
older sibling. Readable siblings retain their negative UID and uniqueness evidence. Seeds never
supply positive binding or counter history.

## Qualification

The worker respected the resource boundary and did not start a JVM when its sandbox could not
establish the required controls. The primary ran the candidate under actual 2 GiB memory, zero
swap, 2 CPU and 256 task limits, with core dumps disabled.

All 93 presence controls passed. The previous store failed 63 of them. Four deliberate defects
were caught separately. The prediction and observed failure sets matched exactly; their original
text comparison differed only in sorting order. Real unprivileged permission probes exercised
unreadable files and unsearchable directories. Genuine absence, readable damage and owned retry
controls remain positive where appropriate. The full store, persistence, manager, framework
fragment and fixture suites also passed.

These are host filesystem and source results, not Android storage or general allocation guarantees.

## Availability and limits

An unavailable header copy withholds all binding eligibility. An unavailable seed or unrelated
slot blocks store writers and new issuance, while otherwise valid binding metadata can remain.
Namespace failures may be reported only as incomplete enumeration, so callers check both facts.
This does not invent missing UID holds: an unreadable index whose identities have no other known
footprint remains a separate recovery and allocator problem.

The private namespace and one serialized writer remain assumptions. Ancestor directories above
the store are trusted. The stream open after stat still has a race window, hard link aliases are
not detected, and the shared strict writer retains its own lower level existence checks. Directory
listing completeness and the supported reader/rollback contract still need qualification. The
existing record size bound is unchanged. The diagnostic dump retains its old status vocabulary
and does not yet expose all unavailability reasons.

No path, inode or absence observation releases a UID by itself. The enclosing retirement must
still own actual producer, work, API, key and data disposition and its confirmed completion.
