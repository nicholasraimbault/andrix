# Public CT fixture

**Status:** a static public fixture supports Android CT delivery tests. This is a
fixture-publication decision, not permission to expose a build/signing environment.

## Design

Serve the original signed CT payload bytes through the dedicated public fixture.
Keep verification keys, signatures and freshness gates unchanged. Static hosting must
not rewrite payloads, attach analytics or manufacture successful security-consumer
responses. The fixture contains no signing credentials or private operator data.

## Verification

Verify payload signatures and freshness before publication; compare the served bytes
and HTTPS behavior against the intended files. Runtime download, validation and
installation remain separate from successful static publication.

See [fixture format and reusable publication instructions](../docs/ct-pages-fixture.md)
and the [Android delivery comparison](2026-09-07-public-ct-runtime.md).
