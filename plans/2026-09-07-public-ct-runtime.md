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

## Result — 09d890f

**CT download and installation passed.** Producer
`09d890f00e9eca90538287d72e03c4d6f9294885` built in 9:55, finishing
2026-09-07 at 06:40:46 UTC. Twenty-eight images and both matching host packages
were frozen. Image extraction found the public prefix in the actual Connectivity
service DEX and the unchanged CT key allowlist. The three experimental WebView
APKs matched their original signed hashes; normal product-policy WebView/DSU
idmaps passed. The APEX, hello, P5 and WebView test APKs matched the previous run.

The fresh ARM64/TCG guest booted with the expected fingerprint and SELinux
enforcing. Charging constraints and the normal CT alarm were retained. All five
public CT URLs reached DownloadProvider status 200 with zero failed attempts.
Android logged installation at 07:19:32 UTC (v3) and 07:19:34 UTC (v2). Normal
shell UID 2000 read the installed files and symlink targets without a policy or
permission change:

| Format | Current target | Installed SHA-256 |
| --- | --- | --- |
| v2 | `logs-89.30` | `29ffe7c6ca8eda4e6e96ebe8507e8e99549427f1c4979b747a344cd439d53683` |
| v3 | `logs-90.5` | `8f20aa979abe8a213ed2ce1bd2326b2afee6510600c05936ab7b69963b8708d8` |

These are the exact published, original-signature-verified bytes. Directories
were 0755, files 0644, owned by system:system and labelled `keychain_data_file`.
No verification, allowlist or install error appeared in the captured CT logs.
This closes the delivery/install blocker, not every TLS-policy or recovery gate.

P4/APEX/read-only `/usr` and P5/ordinary-app execution-boundary checks passed.
The same WebView probe again passed the normal permission dialog, JavaScript
DOM result 42, real same-origin HTTPS 204 and cancel-only hostname-error checks; uninstall
was confirmed. Safe Browsing initialization remained honestly **false**, with
no protection claim.

### Preserved observer errors and metadata correction

The first CT observer incorrectly used the JSON version for both formats. It
rejected v3's `logs-90.5` link despite matching bytes. The primary decoded the
original signed v3 input with the AOSP-built `flatc` and exact r1 schema:
version 90.5, timestamp 1788615428000, independently of the guest filename. v2 is
89.30 with timestamp 1787664926000. Both timestamps passed the 70-day policy.
Only the observer was corrected and rerun; no guest file or signed data changed.
Its first failure remains. The initial internal-flatc invocation also failed
because its built host libc++ search path was absent; that failure was retained.

The host stager now checks both formats independently and records per-format
versions/timestamps/expiry, with the minimum overall expiry. Legacy top-level
version/timestamp are explicitly v2 aliases. The primary reviewed the isolated
change, checked the pinned schema and actual Conscrypt int32 version consumers,
ran the real signed snapshots against the image allowlist, and passed **212 host
tests**. The worker ran no tests; its task worktree was removed. Earlier public
manifests and sealed evidence were not rewritten.

### Network scope and shutdown

Capture covered 06:33:16–07:47:16 UTC, including fixture qualification before VM
assembly, boot/idle, CT installation and the app tests: **36,109 packets**, zero
kernel-reported drops. Guest IPv4 destinations were the private fixture,
local multicast and the public Pages address 185.199.109.153:443. Resolver names
were the owned CT/probe/nonce/wrong-host names. Namespace IPv6 traffic was
link-local/multicast and loopback, not public IPv6 egress. No Google guest
destination was observed in this workload. Fixture recursion/time and local
control-plane traffic are not classified as guest requests; encrypted packet
payloads are not claimed to reveal HTTP status.

The VM and fixture stopped with exit 0 and released the heavy-work lease. The
first wallpaper Google lookup and private-CT failure windows remain failures;
the latter's final DownloadProvider dump reached status 495 after five failed
connection attempts, beyond the earlier status 194 retry observation.

This is a **bounded connected candidate result**, not a supported release or
universal no-Google guarantee. Native ARM/KVM, all conditional/manual app paths,
WebView recovery/config-signer negatives and coordinated update/rollback checks
remain separate open gates. No hardware purchase or privilege workaround follows.
