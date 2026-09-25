// SPDX-License-Identifier: Apache-2.0
// Host byte-container facade, not Android signature verification.
package android.content.pm;
public final class Signature {
 private final byte[] bytes;
 public Signature(byte[] value){bytes=value.clone();}
 public byte[] toByteArray(){return bytes.clone();}
}
