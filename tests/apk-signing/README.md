# APK signing callback probe

This host probe passed the bounded controls below. It is not an Android signing service.
It examines the pinned apksig callback interface before coupling it to the qualified
disposable credential signing vehicle. See the
[artifact plan](../../plans/2026-09-23-protected-apk-artifact.md).

The `KeyConfig.Kms` name describes an extension mechanism. This probe registers one local
provider on a controlled classpath. It does not use a network key service or load a provider
chosen by an APK. Its private key is newly disposable software test material supplied on
stdin, not a protected Android key or an existing project identity.

The observed checks are:

- Capture an owned copy of a small project fixture APK and verify its expected hash.
- Sign only APK Signature Scheme v2 at the declared SDK 37 boundary, measuring the actual
  callback count and algorithm rather than assuming a generic file signature is an APK.
- Verify the complete result and exact certificate before publishing the output bytes.
- Refuse a backend denial, incorrect signature or wrong operation alias without publishing
  an artifact, even if apksig has already produced a local output prefix.
- Keep later caller buffer mutation separate from the captured artifact.

The single scheme and small memory limits are proof bounds, not product signing policy.
System APK updates, v4 sidecars, signing lineages and multiple required signature operations
remain separate integration work. No third party APK or canonical installed artifact should
be resigned as an input to this probe.

`ApkCallbackProbe` uses the same bounded `ANDRK001` private frame as the custody fixture.
Its stdin and any provisioner output must not enter a command logger or public evidence.
Only public artifacts and public transcript metadata may be retained. A caller must wait for
complete process success and verification, not publish an early output prefix.

The provider's thread context is trusted internal plumbing. It does not authenticate a user,
grant approval, establish durable publication or prove protected key custody. Android
integration must retain the concrete artifact, request and crypto operation through approval,
cancellation and completion before this can become part of an owner workflow.
