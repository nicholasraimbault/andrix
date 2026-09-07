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

**HTTPS publication passed on 2026-09-07 at 06:06 UTC.** All five canonical URLs
returned direct HTTPS 200 responses and exact staged body hashes. The downloaded
files then passed the original v2/v3 signature, Android key-allowlist and 70-day
freshness checks. TLS 1.3 verified the hostname against the built Android CA
bundle. GitHub reports HTTPS enforcement enabled; HTTP requests redirect to the
same path on HTTPS.

Initial HTTP routing returned the expected public-key bytes, but strict HTTPS
checks rejected the certificate's hostname and GitHub reported that the requested
certificate did not yet exist. Those failures are retained, not called TLS passes.

The real rootless Unbound fixture was exercised with the new more-specific
`always_transparent` zone. The private probe and nonce resolved to the fixture;
`ct.probe.andrix.org` resolved to GitHub's public addresses rather than the parent
redirect. Renderer regressions and the complete 191-test host suite passed.
This resolver check is not Android DownloadProvider or CT installation proof.

See the [deployment/update contract](../docs/ct-pages-fixture.md). The frozen
`e65e656` image still contains the old private CT URL. Its download failure,
subsequent endpoint/image comparison and full no-Google qualification remain
open; publishing this site alone does not change the guest.

The initial bounded window made 25 strict HTTPS attempts and a post-rebuild
check without success. After a successful unchanged-snapshot rebuild still left
no certificate, the primary consulted GitHub's official certificate-provisioning
troubleshooting guide and performed **one** documented removal/re-save of this
exact custom domain. The same branch/site/domain was restored immediately; no
DNS, payload, key or trust setting changed. A subsequent check observed the
approved certificate, verified all five HTTPS files, and enabled HTTPS enforcement.
The earlier sealed pending checkpoint remains intact.

Observed TLS leaf SHA-256:
`166c9bb61c6e778399373981fee21e92cba699b7685ee871c0fc84011d4cba8a`.
The TLS-observed leaf expires 2026-12-06 at 05:04:10 UTC. This is GitHub-managed
certificate material, not a copied Andrix private key. The temporary resolver
fixture stopped with exit 0; no local readiness monitor, VM or task worktree
remains. The deployment branch and scoped DNS record intentionally remain live.
