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
| Canonical wrong signer | Both copies remained VALID, with only the stored signer changed. APK certificate collection was forced, and the later prior signer check refused admission. Original code, UID, canaries and the peer's key remained. Restoring the original record brought back the original key. |
| Canonical wrong user serial | Both copies remained VALID, with only the stored serial changed. The earlier ownership check refused admission. A healthy boot and original key verification bracketed this case too. |
| Missing PMS package entry | Only the fixture's top level package element was removed from the ordinary settings main file. The independent store kept a VALID pin on an empty UID mapping. Its APK and canaries remained, while a new ordinary APK installed successfully at the predicted different UID. |
| Current database repair | Only the original fixture element was inserted into the current package settings, preserving the newly installed package and its UID. The original APK returned with its original key and canaries. No app data, key database or old whole package database was restored. |

Store checks covered the complete file layout, hashes, ownership, modes, inode, size, timestamps
and SELinux context. Canary checks covered content and file identity. These observations do not
make directory metadata a CE lease or historical identity authority.

The install existing oracle used `--wait` and required its completion callback. At this platform
pin, the shell path without `--wait` can print success despite an internal failure result. The
privileged reservation dump supplied an independent observation of the hold.

## Ordinary settings loss control

The fixture first captured the actual process hosting the package Binder service. A root test
helper retained its PID descriptor, validated the live subject, requested the fixed zygote stops,
and required both that captured process's exit and stopped service states. The exit of a shell
command alone was not a writer completion signal. This does not prove native work retirement.

The XML transformation first ran as a control that retained all package state while moving the
fixture element and reindexing certificate references. A fresh ignored element at the end provided
a positive main parser witness. The test also required unchanged complete package/shared UID maps
and no new settings parse, certificate, fallback or destruction errors. An end marker alone would
not detect an element that was silently dropped.

Only the main file was replaced. Its current original reserve remained untouched as a safe fallback.
After the removal boot, the empty held mapping established that the edited main had been consumed.
The allocator test required that this ID was the actual first hole at or above the observed cursor.
The new APK had to install successfully at the predicted next available ID. A failed install or a
cursor that had already passed the held ID would not qualify exclusion.

Repair inserted the original element before `keyset-settings` in the current XML. That ordering
preserves reference counting during parsing. The repair refused name, app ID and keyset conflicts.
It kept the current reserve containing the new APK, rather than rolling back an earlier database.
Separate per user permissions, restrictions and domain state were not restored or qualified.

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

A signer test initially matched the inner APK directory instead of the enclosing scan directory
reported by PMS. That run failed its oracle despite the expected refusal being logged. A later
control initially treated unrelated stock APK manifest warnings as settings parser errors and
stopped before mutation. Both failures remain separate from their corrected continuations.

All guest runs were bounded and stopped. The successful repair continuations did not restore app
data or a keystore database, reinstall the original APKs, or rerun initialization.

## Evidence boundaries

The image seal is `34b62d75ca2c956d7f2ca7ca5ca0808b82a97c1f02737199a0dabc88039180e2`.
The original failed trial seal is
`d2461089a41cb861dfae9ad8173730d0651d6dbdb0dd81b208973886627f32e8`.
The final successful continuation seal is
`b2b9169ec66bab1a73a85cda147855760ac2b914101893775cd1c9ad344e0a7e`.
Canonical identity fixture producer `ca9db9d` and mapping tool producer `0f23e7a` added no platform
activation. The corrected signer case seal is
`75972d416340f04ad6fe54ef79f1dd787e7cea5b3d85f382f9ecf43c4f176cb2`.
The serial case seal is
`5625204ade4094de46c0610474cc664e3fceb377cd0912423141e6bb33aeb33c`.
The missing mapping and allocator case seal is
`a8d9fba534d4f173a1b2a69635e36a39a82f9b21babc1ea496631d5e1b8d020d`.
Its successful current database repair continuation seal is
`b544c5a0afe14d9c768f65104de125d162a88f44ae41853967053c05f025f54d`.
Intermediate controls, diagnostic and repair failures have separate private seals.

This does not qualify:

- production designation, manager transactions or writer power loss recovery;
- native process entry, live Android UID participation, home provisioning or API effects;
- production owned restoration into an empty held slot, rather than controlled metadata repair;
- preservation or recovery of runtime permissions and other per user policy state;
- locked CE, secondary users, user reuse, general moves or rollback;
- a required system package conflicting with a held UID;
- owned completion of interrupted creation or final retirement.

The next tests must address these joins without treating this bounded reader result as complete
native account or phone qualification.
