# Staged APK file verification restoration

The method fixtures are copied from the pinned Package Installer source before and after
[the local patch](../../patches/grapheneos-2026081300/package-verity.patch).
The [adapter](../../scripts/proof/package_verity.py) verifies the original file, exact
candidate, patch and extracted methods. The Java harness executes those exact method
bodies with supplied file verification state. The upstream body fails on an already
protected APK; the candidate skips redundant setup, accounts for protected bytes and
retains setup failures.

These host cases do not invoke kernel file verification or authenticate APK signatures.
The existing Android V4 verification still measures the file digest, compares the signed
hashing information and verifies the signature after setup. Source inspection, framework
compilation and fresh Android tests are separate gates. A positive flag is not acceptance
of the package, its sidecar, signer or version.

Run the focused host checks with a JDK available:

```
python3 -B -m unittest scripts.proof.tests.test_package_verity -v
```

The source adapter shares the complete framework change fence with the accepted CE
adaptation. It recognizes only exact original or declared candidate bytes. It does not
allow arbitrary Package Installer changes merely because they use the same path.
