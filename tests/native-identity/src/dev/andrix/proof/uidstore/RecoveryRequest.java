// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.uidstore;

/** Bounded fixture inputs. None of these strings grant a UID or key namespace. */
public final class RecoveryRequest {
    public final String operation, nonce, setup, expectedKey;

    public RecoveryRequest(String operation, String nonce, String setup, String expectedKey) {
        if (!"initialize".equals(operation) && !"observe".equals(operation)
                && !"absent".equals(operation)) throw new IllegalArgumentException("operation");
        token(nonce); token(setup);
        if ("observe".equals(operation)) {
            if (expectedKey == null || !expectedKey.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("expected public key digest");
            }
        } else if (expectedKey != null) throw new IllegalArgumentException("unexpected key digest");
        this.operation = operation; this.nonce = nonce; this.setup = setup; this.expectedKey = expectedKey;
    }
    private static void token(String value) {
        if (value == null || !value.matches("[a-z0-9_]{1,48}")) throw new IllegalArgumentException("fixture token");
    }
    public String alias() { return "andrix_uid_recovery_" + setup; }
    public String fileName() { return "uid-recovery-" + setup + ".bin"; }
}
