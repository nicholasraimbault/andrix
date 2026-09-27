# Descriptor copy durability diagnostic

This is a disposable fixture, not an installer, native account operation or recovery authority.
It writes only fresh, exclusively created names under `/data/local/tmp` on Android. The input is a
bounded regular file named `andrix-writeback-input-<32 lowercase hex nonce>.apk`. The output root is
`andrix-writeback-<nonce>`. An existing output refuses; there is no delete or repair command.

`prepare <nonce>` copies the same input into three groups, in this order:

1. `durable`: preallocate, copy, sync the actual writing descriptor, close it, sync the containing
   directory, rename without replacement, and sync the parent directory.
2. `namespace`: preallocate, copy and close without syncing the writing descriptor, rename without
   replacement, then sync only the parent directory.
3. `unsynced`: preallocate, copy, close and rename without any subsequent sync.

The output root is synced before the comparison starts. The checked control finishes before either
unsynced group is written. There is no global sync, delay, VM stop or automatic cleanup. Every
required operation is checked. An error leaves the original names and partial results for the
controller to reconcile, rather than replaying preparation under another identity.

`observe <nonce>` opens the captured namespace with no symbolic link following and reports both
final and staging names. ENOENT is reported separately from errors. Bounded file bytes are returned
as hex for independent hashing by the host, alongside descriptor metadata. Observation does not
sync, rewrite or repair. File paths and inode numbers are observations, not credentials or live
leases. The parent directories above the fixed base belong to the trusted test environment.

Host checks cover copy and sync ordering, exclusive output, malformed arguments, aliases, unreadable
files and six injected sync failures. The Android build excludes both the host path substitution
and the fault injection environment variable. The helper uses ordinary runtime checks, not C
assertions that can disappear in a release build.

A successful prepare acknowledges only the listed operations. The comparison is decided by later
readback after a separately recorded cold stop. Surviving unsynced bytes do not establish durability;
missing or changed bytes must be retained as observed. The test controller owns timing, exact VM
termination and all reconciliation. QMP quit is an unclean guest stop, not a physical power cut.
This fixture changes no APK installation, UID mapping, permission state, app data or keystore.
