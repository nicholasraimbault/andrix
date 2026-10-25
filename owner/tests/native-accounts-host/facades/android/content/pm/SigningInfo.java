// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.content.pm;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
/** Pinned SigningInfo.java:239-244 delegates exact CURRENT signature set comparison.
 * Test signer tokens are inert and do not parse, sign or verify certificates. History is ignored. */
public final class SigningInfo {
    private final String[] current, history;
    public SigningInfo(String[] current, String[] history) {
        this.current=current == null ? null : current.clone();
        this.history=history == null ? null : history.clone();
    }
    public String[] getApkContentsSigners() { return current == null ? null : current.clone(); }
    public boolean signersMatchExactly(SigningInfo other) {
        if (other == null || current == null || other.current == null) return false;
        Set<String> a=new HashSet<>(Arrays.asList(current));
        Set<String> b=new HashSet<>(Arrays.asList(other.current));
        return current.length == other.current.length && a.equals(b);
    }
    public String[] getSigningCertificateHistoryForHostTest() { return history.clone(); }
}
