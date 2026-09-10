# Ordinary APK owner-boundary negative

Optional `AndrixOwnerNegative` is never a product package. It deliberately uses
**the same local lab signer** as the trusted Andrix console, but a different package
name and ordinary install location. No shared UID, APK-declared permissions,
adopted identity or operator grants. GrapheneOS's one implicit OTHER_SENSORS PM
entry is checked explicitly; its grant state is not claimed measured.

The native probe performs an ordinary-identity ServiceManager lookup and attempts
to open the real CE home. Its platform-specific Binder NDK bootstrap API does not
grant it the console's signer/package-scoped SELinux identity. Expected results:
untrusted-app SID, no service handle and home EACCES. These results alone are **not
a PASS**: a host observer must independently establish that the genuine service
and home were live and accessible through the normal foreground console before
and after this negative. Preserve the actual access-denial audit records.

Use normal install/instrumentation/uninstall, inspect the compiled APK/signature/
JNI/permission metadata, and verify removal. This is separate from P5's ordinary
private-execution negative and does not replace it. Nothing here has yet been
qualified on a running Android system.
