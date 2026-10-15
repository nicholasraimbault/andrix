// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principalclosed;

import android.os.Bundle;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;

final class Contract {
    static final String PACKAGE = "dev.andrix.proof.principalclosed";
    static final String SIGNER = "874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3";
    static final String[] ALIASES = {"andrix_b2_state_ec0", "andrix_b2_state_ec1"};
    static final String CHANNEL = "andrix.b2.state";
    static final String SERVICE = PACKAGE + ".B2StateJobService";
    static final int JOB_ID = 21802;
    static final long LATENCY = 2592000000L;
    static final long TRIAL_LIMIT = 604800000L;
    final String operation, nonce, setup, contract, phase, guest, ceToken, deToken;
    final String key0, key1;
    final int uid;
    final long serial;

    Contract(Bundle args) {
        if (args == null) throw new IllegalArgumentException("arguments required");
        operation = text(args, "operation", "initialize|observe");
        Set<String> fields = new HashSet<>(Set.of("operation", "nonce", "setup",
                "contract_sha256", "phase", "guest_binding_sha256", "expected_uid",
                "expected_serial", "ce_token", "de_token"));
        if (operation.equals("observe")) fields.addAll(Set.of("expected_key0", "expected_key1"));
        if (!fields.equals(args.keySet())) throw new IllegalArgumentException("argument fields");
        nonce = text(args, "nonce", "[0-9a-f]{32}");
        setup = text(args, "setup", "[0-9a-f]{32}");
        contract = text(args, "contract_sha256", "[0-9a-f]{64}");
        phase = text(args, "phase", "[a-z][a-z0-9_]{0,47}");
        guest = text(args, "guest_binding_sha256", "[0-9a-f]{64}");
        ceToken = text(args, "ce_token", "[0-9a-f]{32}");
        deToken = text(args, "de_token", "[0-9a-f]{32}");
        if (ceToken.equals(deToken)) throw new IllegalArgumentException("independent tokens");
        uid = Integer.parseInt(text(args, "expected_uid", "1[0-9]{4}"));
        serial = Long.parseLong(text(args, "expected_serial", "0|[1-9][0-9]{0,18}"));
        if (serial < 0) throw new IllegalArgumentException("serial");
        key0 = operation.equals("observe") ? text(args, "expected_key0", "[0-9a-f]{64}") : null;
        key1 = operation.equals("observe") ? text(args, "expected_key1", "[0-9a-f]{64}") : null;
        if (key0 != null && key0.equals(key1)) throw new IllegalArgumentException("distinct keys");
    }

    private static String text(Bundle args, String key, String pattern) {
        Object value = args.get(key);
        if (!(value instanceof String) || !((String) value).matches(pattern)) {
            throw new IllegalArgumentException("argument " + key);
        }
        return (String) value;
    }

    static byte[] ascii(String text) { return text.getBytes(StandardCharsets.US_ASCII); }
    static String hash(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out = new StringBuilder(64);
        for (byte b : digest) out.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return out.toString();
    }
    byte[] canary(boolean ce) {
        return ascii("andrix-b2-canary-v1\nstorage=" + (ce ? "CE" : "DE")
                + "\npackage=" + PACKAGE + "\nuid=" + uid + "\nuser_serial=" + serial
                + "\nsetup=" + setup + "\ntoken=" + (ce ? ceToken : deToken) + "\n");
    }
    byte[] fixtureContract() throws Exception {
        return ascii("andrix-b2-contract-v1\npackage=" + PACKAGE + "\nuid=" + uid
                + "\nuser_serial=" + serial + "\napk_signer_sha256=" + SIGNER + "\nsetup=" + setup
                + "\nkey0_alias=" + ALIASES[0] + "\nkey1_alias=" + ALIASES[1]
                + "\nce_sha256=" + hash(canary(true)) + "\nde_sha256=" + hash(canary(false))
                + "\npermission=android.permission.POST_NOTIFICATIONS\npermission_flags=48"
                + "\npackage_appop=android:vibrate:1\nuid_appop=android:vibrate:default"
                + "\nnotification_setup=channel-bubbles-copy-v1"
                + "\nchannel=andrix.b2.state:2:1:256\nchannel_audio=5:4:0\njob=21802:"
                + PACKAGE + "/" + SERVICE
                + ":null:2592000000\ntrial_limit_ms=604800000\n");
    }
    byte[] intent() throws Exception {
        return ascii("andrix-b2-setup-v1\npackage=" + PACKAGE + "\nuid=" + uid
                + "\nuser_serial=" + serial + "\nsetup=" + setup + "\ncontract_sha256=" + contract
                + "\nce_sha256=" + hash(canary(true)) + "\nde_sha256=" + hash(canary(false)) + "\n");
    }
    void validateContract() throws Exception {
        if (!hash(fixtureContract()).equals(contract)) {
            throw new IllegalArgumentException("host contract mismatch");
        }
    }
}
