// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

/** Finite fixture arguments. Names and displayed IDs are not authorization. */
public final class ProbeArguments {
    public static final String PRINCIPAL = "dev.andrix.proof.principal";
    public static final String PEER = "dev.andrix.proof.principalpeer";
    public static final String CLOSED = "dev.andrix.proof.principalclosed";
    public static final int NOTIFICATION_ID = 7301;
    public final String action;
    public final String targetPackage;
    public final String nonce;
    public final int observeMillis;

    private ProbeArguments(String action, String targetPackage, String nonce, int observeMillis) {
        this.action = action;
        this.targetPackage = targetPackage;
        this.nonce = nonce;
        this.observeMillis = observeMillis;
    }

    public static ProbeArguments parse(String[] args) {
        if (args == null || args.length < 3 || args.length > 4) {
            throw new IllegalArgumentException("expected action, fixture package, nonce, optional observation duration");
        }
        String action = args[0];
        if (!"info".equals(action) && !"post".equals(action)
                && !"cancel".equals(action) && !"observe".equals(action)) {
            throw new IllegalArgumentException("unknown fixture action");
        }
        String target = args[1];
        if (!PRINCIPAL.equals(target) && !PEER.equals(target) && !CLOSED.equals(target)) {
            throw new IllegalArgumentException("not a fixture package");
        }
        if (args[2] == null || !args[2].matches("[a-zA-Z0-9_]{1,64}")) {
            throw new IllegalArgumentException("invalid public fixture nonce");
        }
        int duration = 1500;
        if (args.length == 4) {
            if (args[3] == null || !args[3].matches("[0-9]{1,5}")) {
                throw new IllegalArgumentException("invalid observation duration");
            }
            duration = Integer.parseInt(args[3]);
        }
        if (duration < 0 || duration > 30000) {
            throw new IllegalArgumentException("observation duration outside fixture bound");
        }
        return new ProbeArguments(action, target, args[2], duration);
    }
}
