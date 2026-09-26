# Bounded native identity boot recovery

Status: one disposable Android guest exercised the PMS reader, reservation fences, quarantine
and recovery of its original fixture data and keys. Native execution and production designation
remain disabled. The first complete trial failed, and its later continuations are separate evidence.

This follows the [PMS consumer](2026-09-26-native-store-pms-consumer.md) and uses the
[ordinary UID observers](../tests/native-identity/README.md).

## Vehicle and scope

Producer `fec0da7` built a normal Cuttlefish image with the guarded PMS consumer and diagnostic
dump, plus two separate test APKs. The APKs were not included in the image. The build retained
normal verification and enforcing SELinux. It did not select the delegated work or native factory
vehicles. The framework adaptation was reverted after the build, preserving the existing CE and
Package Installer adaptations in the source checkout.

The test APKs used real Android assigned UIDs, the actual user serial and verified APK signer.
Each created dummy CE/DE canaries and a key in its own AndroidKeyStore namespace. Observations
used fresh recorded nonces and independent public signature verification. Missing data or keys
were never regenerated. Another APK with the same certificate but a different UID could not find
the first APK's fixture state through its own namespace.

The host supplied controlled native slot metadata after capturing those Android facts. That is
fault injection, not a production designation, a live native credential or proof of the writer's
durability. Native account entry remained disabled throughout.

## Observed results

| Case | Observation |
| --- | --- |
| No store | Both APKs ran and retained their original canaries and keys across reboot. The admitted package's install existing operation completed successfully. |
| Healthy slot | The backing APK remained admitted after reboot. PMS reported its held app ID and original mapping. Its install existing operation was refused while the peer's operation succeeded in the same boot. |
| Invalid main, valid reserve | The backing APK remained admitted with its original key and canaries. The invalid main stayed invalid. All recorded store bytes and metadata stayed unchanged across the reader boot. |
| Both rich records damaged | The initial warm reboot stalled during native sensor startup. Later cold continuations of the same guest and unchanged damaged state booted. PMS kept the backing package's setting and UID but did not register its instrumentation. Its original code and canary identity/content remained. The peer continued using its original key. |
| Original record metadata restored | After a checked rewrite of only the original rich records and a cold restart, the backing APK was admitted again. Both original public key fingerprints matched, and both keys signed fresh challenges verified on the host. UID, user serial, APK signer and original canary identity/content matched. |

Store checks covered the complete file layout, hashes, ownership, modes, inode, size, timestamps
and SELinux context. Canary checks covered content and file identity. These observations do not
make directory metadata a CE lease or historical identity authority.

The install existing oracle used `--wait` and required its completion callback. At this platform
pin, the shell path without `--wait` can print success despite an internal failure result. The
privileged reservation dump supplied an independent observation of the hold.

## Failures retained, not relabeled

The original both records damaged reboot did not complete within its 600 second limit. Logs show
PMS completing its constructor and deferring the fixture package. Native sensor startup then did
not finish, while the main thread waited for `sensorservice`. The same damaged state booted on a
later cold restart without a metadata repair. Diagnostic Java and native stacks were collected
then, but they cannot establish the cause of the earlier stall. No timeout or service policy was
weakened to turn that original run into a pass.

A later fixture repair used an ordinary root file copy immediately before stopping the VM. The
next boot exposed two zero filled rich records, despite their expected lengths. The strict
bookend failed. This was not an invocation of the production store writer. The corrected fixture
rewrite used the actual output descriptor's `fsync`, followed by filesystem sync. Its next cold
boot passed the original data and key checks. The failed copy and its producer remain retained.

All guest runs were bounded and stopped. The final successful continuation did not restore app
data or a keystore database, reinstall either APK, or rerun initialization.

## Evidence boundaries

The image seal is `34b62d75ca2c956d7f2ca7ca5ca0808b82a97c1f02737199a0dabc88039180e2`.
The original failed trial seal is
`d2461089a41cb861dfae9ad8173730d0651d6dbdb0dd81b208973886627f32e8`.
The final successful continuation seal is
`b2b9169ec66bab1a73a85cda147855760ac2b914101893775cd1c9ad344e0a7e`.
Intermediate diagnostic, quarantine and repair failures have separate private seals.

This does not qualify:

- production designation, manager transactions or writer power loss recovery;
- native process entry, live Android UID participation, home provisioning or API effects;
- an empty held allocator slot, lost PMS mapping, wrong stored signer or serial;
- locked CE, secondary users, user reuse, general moves or rollback;
- a required system package conflicting with a held UID;
- owned completion of interrupted creation or final retirement.

The next tests must address these joins without treating this bounded reader result as complete
native account or phone qualification.
