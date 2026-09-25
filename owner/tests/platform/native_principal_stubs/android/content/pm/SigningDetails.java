// SPDX-License-Identifier: Apache-2.0
// Host facade, not Android signing lineage verification.
package android.content.pm;
public final class SigningDetails {
 private final Signature[] signatures;
 public SigningDetails(Signature... signatures){this.signatures=signatures;}
 public Signature[] getSignatures(){return signatures;}
}
