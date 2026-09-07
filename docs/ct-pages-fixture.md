# Public CT test fixture

The owner authorized static GitHub Pages publication at
`ct.probe.andrix.org` for the next Certificate Transparency delivery comparison.
This is **test data hosting**, not an Android release or a complete no-Google
qualification. It adds no public listener on the build/signing host and uses
none of its private signing or probe TLS keys.

## Deployment contract

- Repository: `nicholasraimbault/andrix`; default branch remains `master`.
- Pages source: dedicated `gh-pages` branch, root directory. No pre-existing
  Pages site/domain was replaced.
- Exact DNS-only CNAME: `ct.probe.andrix.org` → `nicholasraimbault.github.io`.
  No wildcard, parent `probe.andrix.org`, apex or `.dev` record change.
- Deployment root has `CNAME`, `.nojekyll` and `.gitattributes` preventing text
  conversion or content filters. No Git LFS, Jekyll transformation or analytics.
- Initial data: version 89.30, the same verified public snapshot used in the
  private fixture. Both original signatures, public key and client allowlist
  remain unchanged. The snapshot is not re-signed or reserialized.

The canonical URLs are:

```text
https://ct.probe.andrix.org/certificate_transparency/log_list.pub
https://ct.probe.andrix.org/certificate_transparency/v2/log_list.json
https://ct.probe.andrix.org/certificate_transparency/v2/log_list.sig
https://ct.probe.andrix.org/certificate_transparency/v3/log_list.ctfb
https://ct.probe.andrix.org/certificate_transparency/v3/log_list.sig
```

The additional `manifest.json` records source/freshness/hash metadata; it is not
another Android fetch requirement. These public upstream data retain their own
terms and are not relicensed as original Andrix code.

## Verify each publication

Use [the offline CT stager](../scripts/proof/stage_ct_data.py) against the public
key allowlist extracted from the exact target resource APK. Freeze its five
output byte sequences and metadata before publishing. Preserve original source
fetch records; do not substitute a new key or relabel old data as fresh.

After deployment, require successful hostname-verified HTTPS GETs at all five
canonical paths, not HTML error pages or an unexpected redirect. Compare decoded
HTTP response-body hashes to the staged manifest, then re-run allowlist,
signature and 70-day-age validation on the downloaded files. Recheck the age at
**guest use** time too. Pages/CDN caching does not extend the client's freshness
limit, and static hosting is not an automatic update service. Stage/review a new
snapshot well before expiry and account for the client's retry interval. Pages
caches files independently (600 seconds was observed); an update can briefly mix
old/new generations. Signature failure must retain the last valid generation,
not become a pass. Stale or unavailable data cannot be a successful update.

Pages provides its own public-CA certificate for this exact host. A DNS record
and a successful Pages build do not prove that certificate is ready. Preserve
initial DNS-negative-cache or certificate-name failures. Enforce HTTPS only
when GitHub has provisioned the certificate and independently verify the result;
never use an insecure curl/TLS override to call publication successful.

## Keep public CT outside the private fixture zone

The private Unbound fixture deliberately redirects `probe.andrix.org` and its
nonce descendants to its RFC1918 address. The renderer now adds:

```text
local-zone: "ct.probe.andrix.org." always_transparent
```

This more-specific exception recurses through public DNS; it does not pin Pages
IP addresses or choose another resolver. A real Unbound check must retain the
private probe/nonce answer while returning public Pages addresses for the CT
host. Do not broaden the private TLS certificate or change the parent probe
record to work around this distinction.

## Separate publication from Android consumption

The frozen `e65e656` image still requests
`https://probe.andrix.org/certificate_transparency/`. Publishing this new site
cannot change that image. The next Android comparison needs an explicit new
endpoint patch/image and the qualified DNS exception, with capture before boot.

The earlier DownloadProvider timeout remains a failure with an unproved root
cause. Publication checks do not clear it. Require actual download, original
allowlisted signature verification and log-list installation without permission
grants to the system downloader, protected-broadcast bypasses, direct data
injection or CT disablement. Public IPv6 availability also does not prove IPv6
reachability on the earlier IPv4-only fixture profile.
