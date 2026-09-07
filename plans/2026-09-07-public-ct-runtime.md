# Public CT delivery comparison

The owner authorized continuing from verified public fixture publication to the
Android download/install comparison. Preserve the frozen `e65e656` image and its
private-endpoint failure. This is a new emulated candidate, not native ARM or a
release decision.

## Controlled change

Change only the CT URL prefix in the declared r1 `Config.java` adaptation:

```text
https://probe.andrix.org/certificate_transparency/
→ https://ct.probe.andrix.org/certificate_transparency/
```

The twelve-file/eight-project series remains explicit. Verify/archive the old
applied series, reverse that exact series, verify its pristine bases, then apply
the new complete series normally. Project HEADs/indexes, CT allowlist/signatures,
service scheduling, permissions, WebView APKs and all other endpoint controls
remain unchanged. The regression reconstructs the complete pinned Config file
and requires the prefix to be its only change.

The new fixture must use the already-tested more-specific Unbound public CT zone
while retaining private probe/nonce/DoT/NTP answers. Recheck public HTTPS bodies,
original signatures, allowlisted key and age before guest use. Keep TLS keys in
the separate private service filesystem and product keys outside both sandboxes.
Capture before assembly/boot. Use the exclusive heavy-work lease and the existing
four-vCPU/4096-MiB ARM64 QEMU/TCG route, not a different architecture/artifact.

## Evidence gate

Let the normal CT alarm and DownloadProvider run. Do not send the previously
denied protected broadcast, grant the downloader local-network permission,
inject data or suppress failures.

DownloadProvider 200 is **not installation**. Seek all five expected public URLs
at 200, CT's allowlisted verification and `New logs installed at ...` records,
and, if normal shell policy permits, hashes and symlink targets for:

```text
/data/misc/keychain/ct/v2/current/log_list.json
/data/misc/keychain/ct/v3/current/log_list.ctfb
```

Compare installed bytes to the published snapshot. A denied read is retained,
not bypassed. TLS packet destinations alone cannot expose encrypted HTTP status
or prove installation. Installer completion and Conscrypt's separate age policy
must not be conflated. Claim only the versions and paths actually observed.

Repeat the APEX/`/usr` and ordinary-app boundary checks on the new image. Keep
no-Google capture scope, Android CT installation, WebView behavior, native runtime
and production update/rollback claims separate. Record the actual result here;
no success is implied by this procedure.
