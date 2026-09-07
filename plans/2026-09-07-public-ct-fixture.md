# Authorized public CT fixture

The owner approved publishing the static CT test data through GitHub Pages at
`ct.probe.andrix.org`, with the build/signing host and all private keys remaining
private. This authorizes that exact site and DNS record, not unrelated zones,
hosting purchases, Android permission changes or a release claim.

## Publication

- Repository had no Pages site and no `gh-pages` branch before this operation.
- Dedicated deployment branch: `gh-pages`, root directory; `master` remains the
  project default branch and is not exposed wholesale as the site.
- Initial snapshot commit: `7d5b1597e800df92254c00faa32c2bd3bde2c1c9`.
- Byte-preservation follow-up: `07e708652c166b2d969c7dc8d3ac233140d6f5b6`.
- Exact DNS-only CNAME: `ct.probe.andrix.org` to `nicholasraimbault.github.io`.
  Both authoritative servers and an independent public resolver returned it.
  No parent/apex/`.dev` or wildcard record was changed.
- CT version 89.30 was revalidated before publication: original v2/v3 signatures,
  unchanged Android public-key allowlist and 70-day age gate. The same five
  payload byte sequences are published under `/certificate_transparency/`.
- `.nojekyll` and disabled Git text/content filters preserve those bytes. The
  extra index/manifest describe the experiment; no analytics, proxy, private
  signing material or TLS key is published.

The first Pages creation CLI command returned an empty-response JSON parsing
error. Read-only reconciliation showed the site had been created and built with
the exact branch/domain. No blind duplicate creation or unrelated site overwrite
followed. An explicit same-domain configuration request returned HTTP 204.

## Verification state

Publication is not yet fully qualified over HTTPS. HTTP routing returned the
expected public-key bytes, but initial HTTPS attempts rejected the certificate's
hostname. GitHub's HTTPS-enforcement API explicitly reported that the certificate
did not yet exist. Those failures are retained, not treated as successful TLS.
A bounded verifier uses the built Android CA bundle and requires exact HTTPS 200
bodies, original hashes and no redirects before recording publication success.

The real rootless Unbound fixture was exercised with the new more-specific
`always_transparent` zone. The private probe and nonce resolved to the fixture;
`ct.probe.andrix.org` resolved to GitHub's public addresses rather than the parent
redirect. Renderer regressions and the complete 191-test host suite passed.
This resolver check is not Android DownloadProvider or CT installation proof.

See the [deployment/update contract](../docs/ct-pages-fixture.md). The frozen
`e65e656` image still contains the old private CT URL. Its download failure,
subsequent endpoint/image comparison and full no-Google qualification remain
open; publishing this site alone does not change the guest.

The bounded readiness window made 25 strict HTTPS attempts, followed by one
post-rebuild check; hostname verification still failed. A single explicit Pages
rebuild after public DNS qualification succeeded without changing the snapshot.
GitHub continued reporting no certificate, so HTTPS enforcement was not bypassed
or claimed enabled. Recheck issuance and enforce/verify HTTPS before the Android
comparison; no repeated domain removal/re-addition or provider substitution was
used. The temporary resolver fixture is stopped after preserving its evidence.
