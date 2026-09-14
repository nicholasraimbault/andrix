# Versioned WebView prerequisites and consumer rollback

**Status:** the bounded direct-AOSP experiment demonstrated split consumer rollback
and dependency restoration, while exposing the need to retain rollback dependencies.

## Transaction boundary

Treat a new TrichromeLibrary version as an immutable side-by-side prerequisite, not
an ordinary replacement APK. Install the library first; update the WebView and Config
consumer pair in one rollback-enabled session. An unused staged prerequisite is not
an activated consumer generation.

## Result

Consumer rollback worked when its exact signed library dependency was available.
Manual prerequisite restoration demonstrated the missing dependency condition; it was
not accepted as automatic recovery. The [retention extension](2026-09-07-rollback-retention.md)
addressed deletion and pruning of dependencies still referenced by rollback records.

Manifest-only test generations exercise package mechanics, not a genuine browser
upgrade. Production updates, version migration and power-loss recovery require their
own evidence. These experiments are not adopted GrapheneOS platform changes.
