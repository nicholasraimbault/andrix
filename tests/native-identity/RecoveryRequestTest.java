// SPDX-License-Identifier: Apache-2.0
import dev.andrix.proof.uidstore.RecoveryRequest;

public final class RecoveryRequestTest {
    private static void reject(String op, String nonce, String setup, String hash) {
        try { new RecoveryRequest(op, nonce, setup, hash); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid request accepted");
    }
    public static void main(String[] args) {
        if (!RecoveryRequestTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        for (String op : new String[]{"initialize", "observe", "absent"}) {
            RecoveryRequest request = new RecoveryRequest(op, "request_1", "setup_1",
                    op.equals("observe") ? "a".repeat(64) : null);
            assert request.alias().equals("andrix_uid_recovery_setup_1");
            assert request.fileName().equals("uid-recovery-setup_1.bin");
        }
        reject(null, "n", "s", null); reject("delete", "n", "s", null);
        for (String token : new String[]{null, "", "../other", "UPPER", "space token", "x".repeat(49)}) {
            reject("initialize", token, "s", null);
            reject("observe", "n", token, "a".repeat(64));
        }
        reject("observe", "n", "s", null);
        reject("observe", "n", "s", "A".repeat(64));
        reject("observe", "n", "s", "a".repeat(63));
        reject("initialize", "n", "s", "a".repeat(64));
        reject("absent", "n", "s", "a".repeat(64));
        System.out.println("UID recovery request bounds passed; Android unqualified");
    }
}
